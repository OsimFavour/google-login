import os
import pathlib
import requests
from cachecontrol.wrapper import CacheControl
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from flask import Flask, abort, redirect, render_template, request, session
from forms import LoginForm
from functools import wraps

app = Flask(__name__)
app.secret_key = "herjfmqwd03i2ru3jkfqcdd9302pjd"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "635446910036-1qif2dq6etue3iq01ur88hvcgjsv2vhp.apps.googleusercontent.com"
REDIRECT_URI = "http://127.0.0.1:5000/callback"

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
    if request.method == "POST":
        authorization_url, state = flow.authorization_url()
        session["state"] = state
        print(state)
        return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = CacheControl(request_session)
    token_request = Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/protected_area")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/")
def index():
    form = LoginForm()
    # return "Hello World <a href='/login'><button>Login</button></a>"
    return render_template("index.html", form=form)
   


@app.route("/protected_area")
@login_is_required
def protected_area():
    return "Protected Area Here! <a href='/logout'><button>Logout</buton></a>"


if __name__ == "__main__":
    app.run(debug=True)

