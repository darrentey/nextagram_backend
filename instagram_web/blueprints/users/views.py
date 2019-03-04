from app import app
from flask import Blueprint, render_template
from flask import Flask,render_template,url_for, flash, redirect, request
from instagram_web.blueprints.users.forms import RegistrationForm, LoginForm, UpdateForm
from flask_login import login_user, logout_user, login_required, LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
from models.user import User
from flask_login import login_user, login_required, LoginManager, current_user
from werkzeug.utils import secure_filename
from instagram_web.util.s3_helper import upload_file_to_s3
from instagram_web.util.google_auth import oauth


users_blueprint = Blueprint('users',
                            __name__,
                            template_folder='templates/')

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.get_or_none(User.id == user_id)


ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    
@users_blueprint.route('/new', methods=['GET'])
def new():
    return render_template('new.html')


@users_blueprint.route('/', methods=['POST'])
@login_required
def create():
    pass


@users_blueprint.route('/<username>', methods=["GET"])
def show(username):
    user = User.get_or_none(User.username == username)
    return render_template('users/user.html', user=user)


@users_blueprint.route('/<id>/edit', methods=['GET', 'POST'])
def edit(id):
    form = UpdateForm()
    user = User.get_by_id(id)
    return render_template('users/edit.html', form=form, user=user)

@users_blueprint.route('/<id>/update', methods=['POST'])
def update(id):
    form = UpdateForm()
    user = User.get_by_id(id)
    if form.validate_on_submit():
        update = User.update(
            username=form.username.data,
            email=form.email.data
        ).where(User.id == user.id)
        if update.execute():
            flash('Update Successful', 'success')
            return redirect(url_for('users.edit', id=user.id))
            # Handle what happens when user is updated
        else:
            flash('Error', 'danger')
    return render_template('users/edit.html', form=form, user=user)
            # Handle what happends when user isn't updated 

@users_blueprint.route('/upload', methods=['GET'])
@login_required
def upload():
    return render_template('users/my_profile.html')


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
    return render_template('users/login.html', title='Login', form=form)


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
    return render_template('users/register.html', title='Register', form=form)

@users_blueprint.route('/logout')
@login_required
def logout():
	logout_user()
	flash("You've been logged out!", "success")
	return redirect(url_for('home'))

    
@users_blueprint.route("/upload", methods=["POST"])
def upload_file():

	# A
    if "user_file" not in request.files:
        return "No user_file key in request.files"

	# B
    file    = request.files["user_file"]

    """
        These attributes are also available

        file.filename               # The actual name of the file
        file.content_type
        file.content_length
        file.mimetype

    """

	# C.
    if file.filename == "":
        return "Please select a file"

	# D.
    if file and allowed_file(file.filename):
        file.filename = secure_filename(file.filename)
        output   	  = upload_file_to_s3(file, app.config["S3_BUCKET"])
        return str(output)

    else:
        return redirect("/")


@users_blueprint.route("/login/google")
def google_login():
    redirect_uri = url_for('users.authorize', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@users_blueprint.route('/authorize/google')
def authorize():
    token = oauth.google.authorize_access_token()
    response = oauth.google.get('https://www.googleapis.com/oauth2/v2/userinfo').json()
    print(response)
    user = User.get_or_none(User.email == response['email'])
    if user:
        login_user(user)
        flash('You have been logged in!', 'success')
        return redirect(url_for('home'))  
    # this is a pseudo method, you need to implement it yourself
    return redirect(url_for('home'))