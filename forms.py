from django import forms
from django.contrib.auth.forms import UserCreationForm, PasswordResetForm
from django.contrib.auth.models import User
from .models import Password, Compartir
from django.forms import ModelForm
from django.contrib.auth.models import AbstractUser




class UserRegisterForm(UserCreationForm):
    first_name = forms.CharField(label='first_name')
    email = forms.EmailField()
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Confirmar Password', widget=forms.PasswordInput)


    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2', 'first_name']



class PassRegisterForm(forms.ModelForm):
    usuario = forms.CharField()
    url = forms.URLField()
    contrasena = forms.CharField(widget=forms.PasswordInput)
    nota = forms.CharField(widget=forms.Textarea)


    class Meta:
        model = Password
        fields = ['usuario', 'url', 'contrasena', 'nota']

class Compartirform(forms.ModelForm):
    class Meta:
        model = Compartir
        fields = ['user']
        labels = {
            'user': 'Nombre de usuario',
        }
        widgets = {
            'user': forms.Select(
                attrs={
                    'class': 'form-control',
                }
            ),
        }

