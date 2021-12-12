"""scrum URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.urls import path
from django.conf.urls import include, url
from django.views.generic import TemplateView
from rest_framework.authtoken.views import obtain_auth_token
from board.urls import router



urlpatterns = [
    
    url(r'^api/token/', obtain_auth_token, name='api-token'),
    url(r'^api/', include(router.urls), name='api-root'),
    url(r'^$', TemplateView.as_view(template_name='board/index.html')),
]
