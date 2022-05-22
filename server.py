import base64
import hashlib
import hmac
import json
from typing import Optional
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response


app = FastAPI()

SECRET_KEY = "6c5b00a421982ddd4ea8f48ccdf0cf7631b3b640fdcc19166535fd6d134ff22c"
PASSWORD_SALT = "8534e44611e05e349c257d715b3e7946e2e0baaf40ad3ae2b442016dd906b334"

def sign_data(data : str) -> str:
	return hmac.new(
		SECRET_KEY.encode(),
		msg=data.encode(),
		digestmod=hashlib.sha256
	).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
	username_base64, sign = username_signed.split(".")
	username = base64.b64decode(username_base64.encode()).decode()
	valid_sign = sign_data(username)
	if hmac.compare_digest(valid_sign, sign):
		return username

def verify_password (username: str, password: str) -> bool:
	password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
	stored_password_hash = users[username]["password"].lower()
	return password_hash == stored_password_hash

users = {
	'stepan@gmail.com': {
		'name':'Stepan',
		'password': 'bcf9c120789aa4b8bbc2ccb908730420309e0ae8aba8309732c97720ef0649a8',
		'balance': 1000
	},
	'nastya@gmail.com': {
		'name':'Nastya',
		'password': '94a506c4fc1e8aa2d2e102d449398913eb1ebfc507ee5404a9f5496e79c0e145',
		'balance': 5000
	},
}


@app.get("/")
def index_page (username: Optional[str] = Cookie(default=None)):
	with open('teamplates/login.html','r') as f:
		login_page = f.read()
	if not username:
		return Response(login_page, media_type="text/html")
	valid_username = get_username_from_signed_string(username)
	if not valid_username:
		response = Response(login_page, media_type="text/html")
		response.delete_cookie(key='username')
		return response		
	try:
		user = users[valid_username]
	except KeyError:
		response = Response(login_page, media_type="text/html")
		response.delete_cookie(key='username')
		return response
	return Response(f"Привет: {users[valid_username]['name']}!", media_type = "text/html")


@app.post("/login")
def process_login_page(username : str = Form(...), password : str = Form(...)):
	user = users.get(username)
	if not user or not verify_password(username, password):
		return Response(
			json.dumps({
				'success': False,
				'massage': 'Неверный логин или пароль.'
			}), 
			media_type = "application/json")
	response = Response(
		json.dumps({
				'success': True,
				'massage': f"Привет: {user['name']}!<br /> Баланс: {user['balance']}"
			}),
		media_type = "application/json")
	username_signed = base64.b64encode(username.encode()).decode()+"." +\
		sign_data(username)
	response.set_cookie(key='username', value=username_signed)
	return response
