import os
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware
from google.oauth2 import id_token
from google.auth.transport import requests as grequests
import requests
from urllib.parse import urlencode

config = Config(".env")
CLIENT_ID = config("CLIENT_ID")
CLIENT_SECRET = config("CLIENT_SECRET")
REDIRECT_URI = config("REDIRECT_URI")

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="your-secret-session-key")

GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"

@app.get("/")
def login():
    query_params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent"
    }
    auth_url = f"{GOOGLE_AUTH_ENDPOINT}?{urlencode(query_params)}"
    return RedirectResponse(auth_url)

@app.get("/auth")
async def auth(request: Request, code: str = None):
    if not code:
        return {"error": "No code provided"}

    # Exchange code for token
    token_data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
    }

    response = requests.post(GOOGLE_TOKEN_ENDPOINT, data=token_data)
    token_json = response.json()

    id_token_str = token_json.get("id_token")

    if id_token_str:
        try:
            id_info = id_token.verify_oauth2_token(id_token_str, grequests.Request(), CLIENT_ID)
            return {
                "id_token": id_token_str,
                "client_id": CLIENT_ID
            }
        except ValueError:
            return {"error": "Invalid ID Token"}

    return {"error": "Failed to retrieve ID token"}
