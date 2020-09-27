from django.urls import path, re_path

from . import views


app_name = 'broker'
urlpatterns = [
    path('', views.root, name='index'),
    re_path(r'^register/*$', views.register, name='register'),
    re_path(r'^advertise/*$', views.advertise, name='advertise'),
    re_path(r'^offline/*$', views.offline, name='offline'),
    re_path(r'^assign_init/*$', views.assign_init, name='assign_init'),
    # path('assign_verify/', views.assign_verify, name='assign_verify'),
    re_path(r'^tag/*$', views.on_reputation_tag, name='tag'),
    re_path(r'^update_reputation/*$', views.update_reputation, name='update_reputation'),
    re_path(r'^pub_key/*$', views.pub_key, name='pub_key'),
    re_path(r'^ticket_key/*$', views.ticket_key, name='ticket_key'),
]
