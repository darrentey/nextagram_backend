from app import app
from flask import Flask,render_template,url_for, flash, redirect, request
from instagram_web.blueprints.users.views import users_blueprint
from flask_assets import Environment, Bundle
from .util.assets import bundles

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename



app.config['SECRET_KEY'] = b'9W\xb0\xc5\x0c\x96\re\x0e \xb3\xdb\xde\x94\x00N'

assets = Environment(app)
assets.register(bundles)

app.register_blueprint(users_blueprint, url_prefix="/users")



@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')

@app.route("/user")
def user():
    return render_template('user.html')





