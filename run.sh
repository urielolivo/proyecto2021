#! /bin/bash


sleep 15
python3 -u manage.py makemigrations
python3 -u manage.py migrate
#python3 -u manage.py runserver 0.0.0.0:8080
gunicorn --bind  :8000   FEI_django.wsgi:application --reload

