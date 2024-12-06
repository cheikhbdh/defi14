from django.urls import path
from .views import customer_service_query

urlpatterns = [
    path('agent_query/', customer_service_query, name='agent_query'),
]
