from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from registro import models
import datetime
import sys, os, base64
import hashlib

#para ver a los usuarios repetidos
def repetido(nusuario):
	rep = models.Registro.objects.filter(nick=nusuario.nick)
	if len(rep) > 0:
		return True
	return False

#existencia de usurio
def error(nusuario):
	if repetido(nusuario):
		return True
	return False

def existencia(nick):
	try:
		models.Registro.objects.get(nick=nick)
		return True
	except:
		return False

#funciones para la generacion de llaves
def generar_llaves():
	private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
	public_key = private_key.public_key()
	return private_key, public_key

def convertir_llave_privada_bytes(llave_privada):
	resultado =llave_privada.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.TraditionalOpenSSL,
		encryption_algorithm=serialization.NoEncryption()
	)
	return resultado

def convertir_bytes_llave_privada(contenido_binario):
	resultado = serialization.load_pem_private_key(
		contenido_binario,
		backend=default_backend(),
		password=None)
	return resultado

def convertir_llave_publica_bytes(llave_publica):
	resultado = llave_publica.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)
	return resultado


def convertir_bytes_llave_publica(contenido_binario):
	resultado = serialization.load_pem_public_key(
		contenido_binario,
		backend=default_backend())
	return resultado

#cifrado, descifrado de dato
def cifrar_datos(contra, datos):
	llave_aes = generar_llave_aes_from_password(contra)
	iv= os.urandom(16)
	data_cif = cifrar(datos, llave_aes, iv)
	return data_cif, iv

def descifrar_datos(datos_cif, contra, iv):
	llave_aes = generar_llave_aes_from_password(contra)
	datos = descifrar(datos_cif, llave_aes, iv)
	return datos

#funciones passwd-hashing
def passwd_hash(contra):
	salt=os.urandom(16)
	hashp = hashlib.sha256(salt+contra.encode('utf-8')).digest()
	hash_b64= base64.b64encode(hashp).decode('utf-8')
	salt_b64 = base64.b64encode(salt).decode('utf-8')
	passwdhs = salt_b64+'-$$-'+hash_b64
	return passwdhs

def verificar_passwdHash(nick, passwd):
	try:
		registro = models.Registro.objects.get(nick=nick)
		passwd_cruda = registro.passwd
		salt = base64.b64decode(passwd_cruda.split('-$$-')[0])
		passwd_hash = base64.b64decode(passwd_cruda.split('-$$-')[1])
		passwd_hash_verify = hashlib.sha256(salt+passwd.encode('utf-8')).digest()
		if passwd_hash_verify == passwd_hash:
			return True
		else:
			return False
	except:
		return False

#Funciones aes
def generar_llave_aes_from_password(password):
	password = password.encode('utf-8')
	derived_key = HKDF(algorithm=hashes.SHA256(),
			length=32,
			salt=None,
			info=b'handshake data ',
			backend=default_backend()).derive(password)
	return derived_key

def cifrar(mensaje, llave_aes, iv):
	aesCipher = Cipher(algorithms.AES(llave_aes), modes.CTR(iv),
			backend=default_backend())
	cifrador = aesCipher.encryptor()
	cifrado = cifrador.update(mensaje)
	cifrador.finalize()
	return cifrado

def descifrar(cifrado, llave_aes, iv):
	aesCipher = Cipher(algorithms.AES(llave_aes), modes.CTR(iv),
			backend=default_backend())
	descifrador = aesCipher.decryptor()
	plano = descifrador.update(cifrado)
	descifrador.finalize()
	return plano

#almacenamiento nick
def wrap_llaves(request, usuario):
	llave_aes_usr = os.urandom(16)
	iv_usr = os.urandom(16)
	usuario_cifrado = cifrar(usuario.encode('utf-8'), llave_aes_usr, iv_usr)
	request.session['usuario'] = base64.b64encode(usuario_cifrado).decode('utf-8')
	return (base64.b64encode(llave_aes_usr).decode('utf-8'), 
		base64.b64encode(iv_usr).decode('utf-8'))

def unwrap_llaves(request):
	llave_aes_usr_b64 = request.COOKIES.get('key1', '')
	iv_usr_b64 = request.COOKIES.get('key2', '')
	usuario_cif_b64 = request.session.get('usuario', '')
	usuario_cif = base64.b64decode(usuario_cif_b64.encode('utf-8'))
	llave_aes_usr = base64.b64decode(llave_aes_usr_b64.encode('utf-8'))
	iv_usr = base64.b64decode(iv_usr_b64.encode('utf-8'))
	usuario = descifrar(usuario_cif, llave_aes_usr, iv_usr)
	return usuario


def firmar_datos(registro, passwd, datos):
	private_key_cif_iv_b64 = registro.llave_privada
	private_key_cif_iv = base64.b64decode(private_key_cif_iv_b64)
	iv = private_key_cif_iv.split(b'-$-')[1]
	private_key_cif = private_key_cif_iv.split(b'-$-')[0]
	private_key_bytes = descifrar_datos(private_key_cif, passwd, iv)
	private_key = convertir_bytes_llave_privada(private_key_bytes)
	signature = private_key.sign(datos, ec.ECDSA(hashes.SHA256()))
	return signature

def verificar_datos(registro, signature_b64, datos):
	public_key_bytes = base64.b64decode(registro.llave_publica)
	public_key = convertir_bytes_llave_publica(public_key_bytes)
	signature = base64.b64decode(signature_b64)
	try:
		public_key.verify(signature, datos, ec.ECDSA(hashes.SHA256()))
		return True
	except InvalidSignature:
		return False

def verificar_periodo_tiempo(registro):
	creacion = registro.timestamp
	ahora = datetime.datetime.now(datetime.timezone.utc)
	diferencia = (ahora - creacion).seconds
	if diferencia > 600:
		return False
	else:
		return True

