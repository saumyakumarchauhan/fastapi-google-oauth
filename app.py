import os
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth

# Load environment variables from .env
load_dotenv()

app = FastAPI()

# Add session middleware - needed to store session data like tokens
app.add_middleware(SessionMiddleware, secret_key="super-secret-session-key")

# Configure OAuth for Google with client ID and secret from env
oauth = OAuth()
oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

# Allowed user email for access (replace with your email)
ALLOWED_EMAIL = "24f1000666@ds.study.iitm.ac.in"

@app.get("/")
async def login(request: Request):
    user = request.session.get("user")
    id_token = request.session.get("id_token")

    # If user is already authenticated and email matches
    if user:
        if user.get("email") == ALLOWED_EMAIL:
            return {
                "message": f"Hello {user['email']}, you are logged in.",
                "id_token": id_token
            }
        else:
            # Deny access if email is not allowed
            raise HTTPException(status_code=403, detail="Access forbidden: unauthorized user")

    # Handle OAuth callback with code from Google
    if "code" in request.query_params:
        # Exchange the code for token
        token = await oauth.google.authorize_access_token(request)
        userinfo = token.get("userinfo")
        id_token = token.get("id_token")

        # Check user info and email verification
        if userinfo and userinfo.get("email_verified") and userinfo.get("email") == ALLOWED_EMAIL:
            # Save user info and id_token in session
            request.session["user"] = userinfo
            request.session["id_token"] = id_token
            return RedirectResponse("/")
        else:
            raise HTTPException(status_code=403, detail="Email not verified or unauthorized")

    # Not logged in, redirect user to Google login page
    redirect_uri = request.url._url  # Current URL for redirect after login
    return await oauth.google.authorize_redirect(request, redirect_uri)

# Endpoint to get raw id_token as JSON
@app.get("/id_token")
async def get_id_token(request: Request):
    id_token = request.session.get("id_token")
    user = request.session.get("user")

    if not user or not id_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if user.get("email") != ALLOWED_EMAIL:
        raise HTTPException(status_code=403, detail="Unauthorized user")

    return JSONResponse(content={"id_token": id_token})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, port=8000)
