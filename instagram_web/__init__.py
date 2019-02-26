from app import app
from flask import Flask,render_template,url_for, flash, redirect, request
from instagram_web.blueprints.users.views import users_blueprint
from flask_assets import Environment, Bundle
from .util.assets import bundles
from forms import RegistrationForm, LoginForm
from flask_login import login_user, login_required, LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
from models.user import User
import sqlite3

app.config['SECRET_KEY'] = b'9W\xb0\xc5\x0c\x96\re\x0e \xb3\xdb\xde\x94\x00N'

assets = Environment(app)
assets.register(bundles)

app.register_blueprint(users_blueprint, url_prefix="/users")

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.get_or_none(User.id == user_id)

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

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=generate_password_hash(form.password.data)
        )
        new_user.save()
        flash(f'Account created for {form.username.data}!', 'success')
        return redirect(url_for('home'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        submitted_password = form.password.data
        user = User.get_or_none(User.email == form.email.data)
        if check_password_hash(user.password, submitted_password):
            login_user(user)
            flash('You have been logged in!', 'success')
            return redirect(url_for('home'))  
        else:
             flash('Login unsuccessful. Please check username and password', 'danger')   
    return render_template('login.html', title='Login', form=form)