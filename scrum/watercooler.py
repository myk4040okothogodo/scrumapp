import hashlib
import json
import logging
import os
import signal
import time
import uuid

from os import path, environ
from sys import path as sys_path
from django import setup
sys_path.append('/scrum/')
environ.setdefault('DJANGO_SETTINGS_MODULE' , 'scrum.settings')
setup()
from  tornado.wsgi import WSGIApplication

from urllib.parse import urlparse
from django.core.signing import TimestampSigner, BadSignature, SignatureExpired
from django.utils.crypto import constant_time_compare
from redis import Redis
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.options import define, parse_command_line, options
from tornado.web import Application, RequestHandler, HTTPError
from tornado.websocket import WebSocketHandler
from tornadoredis import Client
from tornadoredis.pubsub import BaseSubscriber

define('debug', default=True, type=bool, help='Run in debug mode')
define('port', default=8080, type=int, help='Server port')
define('allowed_hosts', default=["localhost:8000","127.0.0.1:8000","0.0.0.0:8000"], multiple=True, help='Allowed hosts for cross domain connections')

define('autoreload', default=True, type=bool, help="autoreload script on changes")

MAX_WAIT_SECONDS = 3

"""The 'on_message' and 'on_close' methods are the API defined by WebSocketHandler"""

class RedisSubscriber(BaseSubscriber):
    def on_message(self, msg):
        """ Handle new message on the Redis channel."""
        
        if msg and msg.kind == 'message':
            try:
                message = json.loads(msg.body)
                sender = message['sender']
                message = message['message']
            except(ValueError, KeyError):
                message = msg.body
                sender = None
            subscribers = list(self.subscribers[msg.channel].keys())
            for subscriber in subscribers:
                if sender is None or sender != subscriber.uid:
                    try:
                        subscriber.write_message(message)
                    except tornado.websocket.WebSocketClosedError:
                    #removed dead peer
                        self.unsubscribe(msg.channel, subscriber)
        super().on_message(msg)            


class SprintHandler(WebSocketHandler):
    """ Handles real-time updates to the board."""

    def check_origin(self, origin):
        allowed = super().check_origin(origin)
        parsed = urlparse(origin.lower())
        matched = any(parsed.netloc == host for host in options.allowed_hosts)
        return  allowed or matched
  
    def open(self):
        """Subscribe to sprint on a new connection."""
        #TODO: validate sprint
        self.sprint = None  #.decode('utf-8')
        channel = self.get_argument('channel',  None)
        if not channel:
            self.close()
        else:
            try:
                self.sprint = self.application.signer.unsign(channel, max_age=60 * 30)
            except (BadSignature, SignatureExpired):
                self.close()
            else:
                self.uid = uuid.uuid4().hex
                self.application.add_subscriber(self.sprint, self)

    def on_message(self, message):
        """ Broadcast updates to other interested clients."""
        if self.sprint is not None:
            self.application.broadcast(message,channel=self.sprint, sender=self)

    def on_close(self):
        """ Remove subscription."""
        if self.sprint is not None:
            self.application.remove_subscriber(self.sprint, self)

class UpdateHandler(RequestHandler):
    """ Handle updates from django application. """

    def post (self, model, pk):
        self._broadcast(model, pk, 'add')
    def put(self, model, pk):
        self._broadcast(model, pk, 'update')
    def delete(self, model, pk):
        self._broadcast(model,pk, 'remove')

    def _broadcast(self, model, pk, action):
        signature = self.request.headers.get('X-Signature', None)
        if not signature:
            raise HTTPError(400)
        try:
            result = self.application.signer.unsign(signature, max_age=60 * 1)
        except(BadSignature, SignatureExpired):
            raise HTTPError(400)
        else:
            expected = '{method}:{url}:{body}'.format(
                method = self.request.method.lower(),
                url = self.request.full_url(),
                body = hashlib.sha256(self.request.body).hexdigest())
            if not constant_time_compare(result, expected):
                raise HTTPError(400)
                               
        try:
            body = json.loads(self.request.body.decode('utf-8'))
        except ValueError:
            body = None
        message = json.dumps({

            'model': model,
            'id': pk,
            'action': action,
            'body': body,
            })
        self.application.broadcast(message)
        self.write('OK!')
        
class ScrumApplication(Application):

    def __init__ (self, **kwargs):
        routes = [
            (r'/socket', SprintHandler),
            (r'/(?P<model>task|sprint|user)/(?P<pk>[0-9]+)', UpdateHandler),
            ]
        
        super().__init__(routes, **kwargs)
        self.subscriber = RedisSubscriber(Client())
        self.publisher = Redis()
        self._key = os.environ.get('WATERCOOLER_SECRET', 'pTyz1dzMeVUGrb0Su4QXsP984qTlvQRHpFnnlHuH ')
        self.signer = TimestampSigner(self._key)

    def add_subscriber(self, channel, subscriber):
        self.subscriber.subscribe(['all', channel], subscriber)
        
    def remove_subscriber(self, channel, subscriber):
        self.subscriber.unsubscribe(channel, subscriber)
        self.subscriber.unsubscribe('all', subscriber)

    def broadcast(self, message, channel=None, sender=None):
        channel = 'all' if channel is None else channel
        message = json.dumps({
            'sender': sender and sender.uid,
            'message': message
            })
        self.publisher.publish(channel, message)




def shutdown(server):
    logging.info(' Stop all server functions...')
    server.stop()
    logging.info('Shutting down in %s seconds ...', MAX_WAIT_SECONDS)
    io_loop = IOLoop.instance()

    deadline = time.time() + MAX_WAIT_SECONDS

    def stop_loop():
        now = time.time()
        if now < deadline :
            io_loop.add_timeout(now + 1, stop_loop)
        else:
            io_loop.stop()
            logging.info('shutdown')
    stop_loop()        


if __name__ == "__main__":
    parse_command_line()
    #application = ScrumApplication(debug=options.debug)
    application = tornado.wsgi.WSGIApplication(debug=options.debug)
    server = HTTPServer(application)
    server.listen(options.port)
    signal.signal(signal.SIGINT, lambda sig, frame: shutdown(server))
    signal.signal(signal.SIGTERM, lambda sig, frame: shutdown(server))
    logging.info('starting server on localhost:{}'.format(options.port))
    IOLoop.instance().start()
