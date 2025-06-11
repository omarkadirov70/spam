from django.urls import path
from . import views

urlpatterns = [
    path('', views.upload, name='upload'),
    path('stats/', views.stats, name='stats'),
    path('api/scan/', views.upload_ajax, name='upload_ajax'),
]
