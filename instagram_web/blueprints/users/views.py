from app import app
from flask import Blueprint, render_template
from flask import Flask,render_template,url_for, flash, redirect, request
from instagram_web.blueprints.users.forms import RegistrationForm, LoginForm
from flask_login import login_user, logout_user, login_required, LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
from models.user import User
from flask_login import login_user, login_required, LoginManager


users_blueprint = Blueprint('users',
                            __name__,
                            template_folder='templates/users')

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.get_or_none(User.id == user_id)


@users_blueprint.route('/new', methods=['GET'])
def new():
    return render_template('new.html')


@users_blueprint.route('/', methods=['POST'])
def create():
    pass


@users_blueprint.route('/<username>', methods=["GET"])
def show(username):
    pass


@users_blueprint.route('/', methods=["GET"])
def index():
    return "USERS"


@users_blueprint.route('/<id>/edit', methods=['GET'])
def edit(id):
    pass


@users_blueprint.route('/<id>', methods=['POST'])
def update(id):
    pass

@users_blueprint.route('/upload', methods=['POST'])
def upload():
    return render_template('users/edit_profile_pic.html')


@users_blueprint.route("/login", methods=['GET', 'POST'])
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


@users_blueprint.route("/register", methods=['GET', 'POST'])
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

@users_blueprint.route('/logout')
@login_required
def logout():
	logout_user()
	flash("You've been logged out!", "success")
	return redirect(url_for('home'))