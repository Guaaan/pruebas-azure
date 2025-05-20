import os
from flask import Flask, redirect, request, session, url_for
import requests
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
from openai import AzureOpenAI

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuración
CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
TENANT_ID = os.getenv("AZURE_TENANT_ID")
REDIRECT_URI = os.getenv("REDIRECT_URI")  # Debe ser https://127.0.0.1:3000/callback
SCOPE = "https://cognitiveservices.azure.com/.default"

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"

AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
DEPLOYMENT_NAME = os.getenv("AZURE_OPENAI_DEPLOYMENT")
API_VERSION = "2023-05-15"


@app.route('/')
def home():
    """Página de inicio con enlace para iniciar sesión"""
    return '<h1>¡Hola! Flask está corriendo en HTTPS.</h1><a href="/login">Login with Microsoft</a>'


@app.route('/login')
def login():
    """Redirecciona al login de Microsoft"""
    auth_url = (
        f"{AUTHORITY}?client_id={CLIENT_ID}"
        f"&response_type=code"
        f"&redirect_uri={REDIRECT_URI}"
        f"&response_mode=query"
        f"&scope=openid+profile+email+{SCOPE}"
    )
    return redirect(auth_url)


@app.route('/callback')
def callback():
    """Proceso de autenticación y obtención del token"""
    code = request.args.get('code')

    # Verificar si se recibió el código
    if not code:
        return "Error: No se recibió el código de autenticación", 400

    # Solicitar el token
    token_data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
        "code": code,
        "scope": SCOPE
    }

    response = requests.post(TOKEN_URL, data=token_data)
    response_data = response.json()

    # Verificar si se obtuvo el token correctamente
    if "access_token" not in response_data:
        error_description = response_data.get("error_description", "Error desconocido")
        return f"Error al obtener el token: {error_description}", 400

    # Guardar el token en la sesión
    session["access_token"] = response_data["access_token"]

    # Redirigir al endpoint de Azure OpenAI
    return redirect(url_for("ask_openai"))


@app.route('/ask_openai')
def ask_openai():
    """Realiza una solicitud al modelo OpenAI"""
    token = session.get("access_token")
    if not token:
        return redirect(url_for("login"))

    try:
        # Configurar el cliente OpenAI
        client = AzureOpenAI(
            api_version=API_VERSION,
            azure_endpoint=AZURE_OPENAI_ENDPOINT,
            azure_ad_token=token
        )

        response = client.chat.completions.create(
            model=DEPLOYMENT_NAME,
            messages=[{"role": "user", "content": "Hola, ¿cómo estás?"}],
            max_tokens=50,
            temperature=0.7
        )

        completion = response.choices[0].message.content.strip()
        return f"Respuesta del modelo: {completion}"

    except Exception as e:
        return f"Error al solicitar la respuesta de OpenAI: {e}"


if __name__ == "__main__":
    # Ejecutar en HTTPS
    app.run(ssl_context=("cert.pem", "key.pem"), host="0.0.0.0", port=3000)
