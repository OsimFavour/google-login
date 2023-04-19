import os
import pathlib
import requests
from cachecontrol.wrapper import CacheControl
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from flask import Flask, abort, redirect, render_template, url_for, request, session
from forms import LoginForm
from functools import wraps

app = Flask(__name__)
app.secret_key = "herjfmqwd03i2ru3jkfqcdd9302pjd"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "635446910036-1qif2dq6etue3iq01ur88hvcgjsv2vhp.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
REDIRECT_URI = "http://127.0.0.1:5000/callback"
JAVASCRIPT_ORIGINS = "http://127.0.0.1:5000"

client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")


flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.profile", "openid"],
    redirect_uri=REDIRECT_URI
    )


# def login_is_required(function):
#     def wrapper(*args, **kwargs):
#         if "google_id" not in session:
#             return abort(401)
#         else:
#             return function()
#     return wrapper


def login_is_required(function):
    @wraps(function)
    def google_wrapper(*args, **kwargs):
        if "google_id" not in session:
            return redirect("/login")
        else:
            return function()
    return google_wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    # if request.method == "POST":
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI],
                "javascript_origins": [JAVASCRIPT_ORIGINS],
            }
        },
        scopes=["openid", "email", "profile"],
    )
    authorization_url, state = flow.authorization_url(
        access_type="offline", prompt="consent"
    )
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    # Verify the state parameter against the one we stored in the session
    if session.get("state") != request.args.get("state"):
        return redirect(url_for("index"))

    # Exchange the authorization code for an access token
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI],
                "javascript_origins": [JAVASCRIPT_ORIGINS],
            }
        },
        scopes=["openid", "email", "profile"],
        state=session.get("state"),
    )

    flow.fetch_token(authorization_response=request.url)

    # Verify the token and retrieve the user's profile information
    idinfo = id_token.verify_oauth2_token(
        flow.credentials.id_token, Request(), GOOGLE_CLIENT_ID
    )
    print(idinfo)

    # Store the user's profile information in the session
    session["google_id"] = {
        "id": idinfo["sub"],
        "name": idinfo["name"]
    }

    return redirect(url_for("protected_area"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/")
def index():
    # form = LoginForm()
    return "Hello World <a href='/login'><button>Login</button></a>"
	# return """
    # <form action="/login">
    #     <button type="submit">Log in with Google</button>
    # </form>
    # """
    # return render_template("index.html", form=form)
    

@app.route("/protected_area")
# @login_is_required
def protected_area():
    return "Protected Area Here! <a href='/logout'><button>Logout</buton></a>"


if __name__ == "__main__":
    app.run(debug=True)

