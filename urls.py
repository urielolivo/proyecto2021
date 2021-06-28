from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib.auth.forms import *
from FEI import views as FEI_views
from django.contrib.auth.models import User
from django.contrib.auth import views as auth_views

#from account.forms import EmailValidationOnForgotPassword


urlpatterns = [
    path('inicio', views.index, name='index'),
    path('perfil/', views.perfil, name='perfil'),
    path('perfil/<str:username>/', views.perfil, name='perfil'),
    path('password/eliminar/<int:password_id>', views.eliminarpassword, name='eliminarpassword'),
    path('registro/', views.registro, name='registro'),
    path('login/', LoginView.as_view(template_name='social/login.html'), name='login'),
    path('logout/', LogoutView.as_view(template_name='social/logout.html'), name='logout'),
    path('password/', views.password, name='password'),
    path('password/editar/<int:password_id>', views.editarpassword, name='editarpassword'),
    path('password/actualizar/<int:password_id>', views.actualizaralumno, name='actualizaralumno'),
    path('compartir/<int:password_id>', views.compartir, name='compartir'),
    path('doblefactor/',views.doblefactor, name='doblefactor'),
    path('paginafactor/', views.paginafactor, name='paginafactor'),
    path('', views.index, name='index'),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
