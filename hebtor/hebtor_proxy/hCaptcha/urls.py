from django.urls import path

from . import views


app_name = 'hCaptcha'
urlpatterns = [
    path('', views.payment, name='payment'),
]
