from django.http import HttpResponse
from django.template import Template, Context
from django.template.loader import render_to_string
from django.shortcuts import render, redirect
from cryptography.hazmat.backends import default_backend
from registro import models
from firmas import operaciones, settings
from firmas.decoradores import *
from django import forms
from django.http import HttpResponse
import base64
import datetime

def logeo(request):
	t = 'logeo.html'
	if request.method == 'GET' and request.session.get('logueado', False):
		return redirect('/firmar_archivo')
	elif request.method == 'GET':
		return render(request, t)
	elif request.method == 'POST':
		user = request.POST.get('user','').strip()
		passwd = request.POST.get('passwd','').strip()
		try:
			usuario = models.Registro.objects.get(nick=user)
			if operaciones.verificar_passwdHash(user, passwd):
				respuesta = redirect('/firmar_archivo')
				llave_aes_usr, iv_usr = operaciones.wrap_llaves(request, user)
				respuesta.set_cookie('key1', llave_aes_usr, httponly=True, samesite='Strict')
				respuesta.set_cookie('key2', iv_usr, httponly=True, samesite='Strict')
				request.session['logueado'] = True
				request.session.set_expiry(18000)
				return respuesta
			else:
				errores = 'Contraseña incorrecta'
				return render(request, t, {'ERRORES': errores})
		except:
			errores = 'Usuario no registrado'
			return render(request, t, {'ERRORES': errores})

def registro(request):
	template = 'formulario.html'
	if request.method == 'GET':
		return render (request, template)
	elif request.method == 'POST':
		nombre = request.POST.get('nom','').strip()
		usuario = request.POST.get('usuario','').strip()
		contra = request.POST.get('contra','').strip()
		correo = request.POST.get('corre','').strip()

		nusuario = models.Registro()
		errores = operaciones.error(nusuario)

		vacio = ''
		if nombre == vacio or usuario == vacio or contra == vacio or correo == vacio:
			return render(request, template, {'ERRORES': 'Todos los campos deben ser completados.'})

		try:
			registro = models.Registro.objects.get(nick=usuario)
			contexto = {'ERRORES': 'Usuario ya registrado'}
			return render(request, template, contexto)
		except:
			nusuario.nombre  = nombre
			nusuario.nick = usuario  
			nusuario.correo = correo

			private_key, public_key = operaciones.generar_llaves()
			private_key_bytes = operaciones.convertir_llave_privada_bytes(private_key)
			public_key_bytes = operaciones.convertir_llave_publica_bytes(public_key)
			private_key_cif, iv = operaciones.cifrar_datos(contra, private_key_bytes)

			passwd_hashing = operaciones.passwd_hash(contra)
			nusuario.passwd = passwd_hashing

			nusuario.llave_privada = base64.b64encode(private_key_cif + b"-$-" + iv).decode('utf-8')
			nusuario.llave_publica = base64.b64encode(public_key_bytes).decode('utf-8')
			nusuario.timestamp = datetime.datetime.now(datetime.timezone.utc)

			nusuario.save()	
			return redirect('/logeo')

@esta_logueado
def firmar_archivo(request):
	template = 'subir.html'
	user = operaciones.unwrap_llaves(request)
	if request.method == 'GET':
		try:
			usuarios = models.Registro.objects.all()
			return render (request, template, {'usuarios': usuarios})
		except:
			return render (request, template, {'ERRORES': 'Problemas con la Base de Datos'})	

	elif request.POST.get('firmar_', None) == 'firmar':
		uploaded_file = request.FILES['file_firma']
		contenido = uploaded_file.read()
		user = operaciones.unwrap_llaves(request)
		passwd = request.POST.get('passwd',' ').strip()
		try:
			registro = models.Registro.objects.get(nick=user.decode('utf-8'))
			usuarios = models.Registro.objects.all()
			if operaciones.verificar_passwdHash(user.decode('utf-8'), passwd):
				if not operaciones.verificar_periodo_tiempo(registro):
					return render (request, template, {'ERRORES': 'Llaves Invalidas, necesita renoverlas.', 'usuarios': usuarios})
				
				archivo_firmado = base64.b64encode(operaciones.firmar_datos(registro, passwd, contenido)).decode('utf-8')
				rendered = render_to_string(template)
				respuesta = HttpResponse(rendered)
				respuesta = HttpResponse(archivo_firmado, content_type="application/txt")
				respuesta['Content-Disposition'] = 'inline; filename=' + uploaded_file.name.split('.')[0] + '.signature'
				return respuesta
			else:
				return render (request, template, {'ERRORES': 'Contraseña Incorrecta.', 'usuarios': usuarios})

		except:
			return render (request, template, {'ERRORES': 'Problemas con el usuario', 'usuarios': usuarios})

	elif request.POST.get('verificar_', None) == 'verificar':
		uploaded_file = request.FILES['file_archivo']
		uploaded_file_firma = request.FILES['file_firmado']
		contenido_firma = uploaded_file_firma.read()
		contenido_file = uploaded_file.read()
		usuario = request.POST.get('usuarios', '').strip()
		try:
			usuarios = models.Registro.objects.all()
			registro = models.Registro.objects.get(nick=usuario)
			
			if not operaciones.verificar_periodo_tiempo(registro):
				if operaciones.verificar_datos(registro, contenido_firma, contenido_file):
                                        return render (request, template, {'ERRORES': 'Firma invalida: llaves de usuario fuera de tiempo, favor de solicitar una firma nueva para el documento.', 'usuarios': usuarios})
				else:
					pass

			if operaciones.verificar_datos(registro, contenido_firma, contenido_file):
				return render (request, template, {'ERRORES': 'Firma valida', 'usuarios': usuarios})
			return render (request, template, {'ERRORES': 'Firma invalida', 'usuarios': usuarios})
		except:
			return render (request, template, {'ERRORES': 'Problemas con el usuario, contacte al administrador', 'usuarios': usuarios})

	elif request.method == 'POST':
		passwd = request.POST.get('password',' ').strip()
		user = operaciones.unwrap_llaves(request)
		try:
			usuarios = models.Registro.objects.all()
			registro = models.Registro.objects.get(nick=user.decode('utf-8'))
			if not operaciones.verificar_passwdHash(user.decode('utf-8'), passwd):
				return render (request, template, {'ERRORES': 'Contraseña incorrecta'})
			else:
				private_key, public_key = operaciones.generar_llaves()
				private_key_bytes = operaciones.convertir_llave_privada_bytes(private_key)
				public_key_bytes = operaciones.convertir_llave_publica_bytes(public_key)
				private_key_cif, iv = operaciones.cifrar_datos(passwd, private_key_bytes)

				registro.llave_privada = base64.b64encode(private_key_cif + b"-$-" + iv).decode('utf-8')
				registro.llave_publica = base64.b64encode(public_key_bytes).decode('utf-8')
				registro.timestamp = datetime.datetime.now(datetime.timezone.utc)
				registro.save()
				return render (request, template, {'ERRORES': 'Llaves actualizadas', 'usuarios': usuarios})
		except:
			return render (request, template, {'ERRORES': 'Problemas con el usuario, contacte al administrador', 'usuarios': usuarios})

@esta_logueado
def renovar_llaves(request):
	template = 'renovar.html'
	if request.method == 'GET':
		return render (request, template)

@esta_logueado
def logout(request):
	request.session.flush()
	respuesta = redirect('/logeo')
	respuesta.delete_cookie('key1')
	respuesta.delete_cookie('key2')
	return respuesta
