
The flow of authorisation code with PKEC Grant model:

User visits / (homepage).

If authenticated, show “Welcome <username>”.

If not authenticated, show a message “You need access. Please log in.” with a login link.

Login uses PingFederate Authorization Code Flow with PKCE.



---

📄 Document: Django + PingFederate (OIDC + PKCE) Authentication

1. Prerequisites

Python 3.9+

Django 4.x or 5.x

Requests library (pip install requests)

A running PingFederate server with:

Authorization Endpoint: https://<ping-domain>/as/authorization.oauth2

Token Endpoint: https://<ping-domain>/as/token.oauth2

Client configured in PingFederate (with Authorization Code + PKCE enabled).

Redirect URI set to your app’s callback, e.g. http://127.0.0.1:8000/callback/.




---

2. Create Django Project

mkdir django_oidc_demo && cd django_oidc_demo
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

pip install django requests
django-admin startproject mysite .
python manage.py startapp core


---

3. Configure Django Settings

Edit mysite/settings.py:

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'core',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
]

ROOT_URLCONF = 'mysite.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / "templates"],  # Add this
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

STATIC_URL = 'static/'

# ---- PingFederate OIDC Config ----
PING_AUTH_URL = "https://ping.example.com/as/authorization.oauth2"
PING_TOKEN_URL = "https://ping.example.com/as/token.oauth2"
PING_CLIENT_ID = "your-client-id"
REDIRECT_URI = "http://127.0.0.1:8000/callback/"
PING_SCOPE = "openid profile email"


---

4. PKCE Utilities

Create core/pkce.py:

import secrets, hashlib, base64

def generate_code_verifier(length=64):
    return secrets.token_urlsafe(length)[:128]

def code_challenge_from_verifier(verifier):
    sha = hashlib.sha256(verifier.encode('ascii')).digest()
    return base64.urlsafe_b64encode(sha).rstrip(b"=").decode('ascii')


---

5. Views for Auth Flow

Edit core/views.py:

import secrets, requests
from django.conf import settings
from django.shortcuts import redirect, render
from django.http import HttpResponse
from urllib.parse import urlencode
from .pkce import generate_code_verifier, code_challenge_from_verifier

# ---- Homepage ----
def home(request):
    user = request.session.get("user")
    if user:
        return HttpResponse(f"<h1>Welcome {user['name']}</h1>")
    else:
        return HttpResponse('<h1>You need access.</h1><a href="/login/">Login</a>')

# ---- Start Login ----
def login_start(request):
    verifier = generate_code_verifier()
    challenge = code_challenge_from_verifier(verifier)
    state = secrets.token_urlsafe(16)

    request.session["pkce_code_verifier"] = verifier
    request.session["oidc_state"] = state

    params = {
        "response_type": "code",
        "client_id": settings.PING_CLIENT_ID,
        "redirect_uri": settings.REDIRECT_URI,
        "scope": settings.PING_SCOPE,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return redirect(settings.PING_AUTH_URL + "?" + urlencode(params))

# ---- Callback ----
def callback(request):
    error = request.GET.get("error")
    if error:
        return HttpResponse("Auth failed: " + error, status=400)

    code = request.GET.get("code")
    state = request.GET.get("state")

    if state != request.session.get("oidc_state"):
        return HttpResponse("Invalid state", status=400)

    verifier = request.session.get("pkce_code_verifier")
    if not verifier:
        return HttpResponse("Missing PKCE verifier", status=400)

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.REDIRECT_URI,
        "client_id": settings.PING_CLIENT_ID,
        "code_verifier": verifier,
    }

    resp = requests.post(settings.PING_TOKEN_URL, data=data, headers={"Accept": "application/json"})
    if resp.status_code != 200:
        return HttpResponse("Token exchange failed: " + resp.text, status=resp.status_code)

    tokens = resp.json()
    # Example: decode ID token if needed, here we just save
    request.session["user"] = {"name": "Authenticated User", "tokens": tokens}

    return redirect("/")


---

6. URLs

Edit mysite/urls.py:

from django.contrib import admin
from django.urls import path
from core import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home, name='home'),
    path('login/', views.login_start, name='login'),
    path('callback/', views.callback, name='callback'),
]


---

7. Templates (Optional)

Create templates/home.html if you prefer HTML instead of inline responses.


---

8. Run App

python manage.py migrate
python manage.py runserver

Visit:

http://127.0.0.1:8000/ → If not logged in, you see “You need access”.

Click login → redirected to PingFederate login.

After authentication → redirected back to / and see “Welcome Authenticated User”.



---

9. Security & Next Steps

✅ Validate ID token (signature, claims). Use python-jose or Authlib.

✅ Replace "Authenticated User" with actual claims from ID token (sub, email, name).

✅ Add logout (clear session).

✅ Use HTTPS in production.

✅ Use Django’s User model for real integration.


