import os
import pathlib
import requests
from cachecontrol.wrapper import CacheControl
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from flask import Flask, abort, redirect, render_template, url_for, request, session
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from forms import LoginForm
from functools import wraps

app = Flask(__name__)
app.secret_key = "herjfmqwd03i2ru3jkfqcdd9302pjd"
app.app_context().push()


## CREATE DATABASE
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///user-login.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# login_manager = LoginManager(app)


os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "635446910036-1qif2dq6etue3iq01ur88hvcgjsv2vhp.apps.googleusercontent.com"
REDIRECT_URI = "http://127.0.0.1:5000/callback"

client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")


flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.profile", "openid"],
    redirect_uri=REDIRECT_URI
    )


## CREATE TABLE
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)

    def __repr__(self):
        return f"<User {self.email}>"

# db.drop_all()

db.create_all()

# Load user from User ID
# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))


def login_is_required(function):
    @wraps(function)
    def google_wrapper(*args, **kwargs):
        if "google_id" not in session:
            return redirect("/login")
        else:
            return function()
    return google_wrapper


@app.route("/")
# @login_is_required
def home():
    all_users = User.query.all()
    return render_template("home.html", users=all_users)


# @app.route("/user-login", methods=["GET", "POST"])
# def user_login():
#     form = LoginForm()
#     if form.validate_on_submit():
#         email = form.emails.data
#         password = form.passwords.data

#         new_user = User(email=email, password=password)
#         print(new_user)
#         db.session.add(new_user)
#         db.session.commit()
#         return redirect(url_for("home"))
#     return render_template("index.html", title="Login", form=form)

@app.route("/user-login", methods=["GET", "POST"])
def user_login():
    form = LoginForm()
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        new_user = User(email=email, password=password)
        print(new_user)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("index.html", title="Login", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        authorization_url, state = flow.authorization_url()
        session["state"] = state
        print(state)
        return redirect(authorization_url)
    # return render_template("home.html")
    return redirect(url_for("home"))


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
    # session["google_id"] = id_info.get("sub")
    # session["name"] = id_info.get("name")
    user = User.query.filter_by(id=id_info['sub']).first()
    if user is None:
        user = User(id=id_info['sub'])
        db.session.add(user)
        db.session.commit()
  
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/protected_area")
   


@app.route("/protected_area")
@login_is_required
def protected_area():
    return "Protected Area Here! <a href='/logout'><button>Logout</buton></a>"


if __name__ == "__main__":
    app.run(debug=True)

