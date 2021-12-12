from  django_filters.rest_framework import BooleanFilter, FilterSet, DateFilter

from django.contrib.auth import get_user_model

from .models import Sprint, Task


User = get_user_model()


class NullFilter(BooleanFilter):
    """Filter on a field set as null or not."""
    
    def filter(self, qs, value):
        if value is not None:
            return qs.filter(**{'%s__isnull' % self.name: value})
        return qs
        
        
class SprintFilter(FilterSet):
    
    end_min = DateFilter(name='end', lookup_type='gte')
    end_max = DateFilter(name='end', lookup_type='lte')
    
    class Meta:
        model = Sprint
        fields = ('end_min', 'end_max', )


class TaskFilter(FilterSet):
    
    backlog = NullFilter(name='sprint')
    
    class Meta:
        model = Task
        fields = ('sprint', 'status', 'assigned', 'backlog', )
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.filters['assigned'].extra.update(
        	{'to_field_name': User.USERNAME_FIELD})                        

                                
                                
