from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_wtf import FlaskForm
from flask_gravatar import Gravatar
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
# from forms import LoginForm, RegisterForm, CreatePostForm, CommentForm
from functools import wraps
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)
## gravatar are used for picture that you see when a users comments

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blogg.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##WTForm
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField(label='Email', validators=[DataRequired(), Email()])
    password = StringField(label='Password')
    submit = SubmitField("Sign me up")

class LoginForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired(), Email()])
    password = StringField(label='Password')
    submit = SubmitField("LOGIN")

#comment form
class CommentForm(FlaskForm):
    body = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")



##CONFIGURE TABLE
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

#*******Add parent relationship*******#
    #"comment_author" refers to the comment_author property in the Comment class.


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")

###Establish a One to Many relationship between each BlogPost object (Parent) and Comment object (Child).
# Where each BlogPost can have many associated Comment objects.
#***************Parent Relationship*************#


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    comment_author = relationship("User", back_populates="comments")
    text = db.Column(db.Text, nullable=False)
# db.create_all()

   #*******Add child relationship*******#
    #"users.id" The users refers to the tablename of the Users class.
    #"comments" refers to the comments property in the User class.
##author property of blogpost is now a User object so author.name, author.email etc.
###### author.name provides the name of the user that wrote the blog post



###decorator function so if a user is not logged in and not ID:1 (admin), they cannot manually get to /new-post, delete, edit post
##### only admin will be able to do that
def admin_only(f):
    @wraps(f)
    def decorated_function(*args,**kwargs):   ##copied from the link: https://flask.palletsprojects.com/en/1.1.x/
        # patterns/viewdecorators/#login-required-decorator
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)       ####abort is a function from functools
        ###otherwise continue with the function
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET","POST"])
def register():
    login_form = RegisterForm()
    if login_form.validate_on_submit():
        if User.query.filter_by(email=login_form.email.data).first():
            #user already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        else:
            email = login_form.email.data
            password = login_form.password.data
            hash_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            user = login_form.name.data
            new_user = User(
                name = user,
                password = hash_password,
                email = email,
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user) ########this logins the user using the new username ###
            return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=login_form)



@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        passwordd = form.password.data

        user = User.query.filter_by(email=email).first()
        # print(check_password_hash(user.password, password))

        if not user:
            #user does not exist
            flash("User does not exist, please try again!")
            return redirect(url_for('login'))

        elif not check_password_hash(user.password, passwordd):
            # password does not match
            flash("incorrect password, please try again!")
            return redirect(url_for('login'))

        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form, logged_in = current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=form.body.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, comment_form=form, current_user=current_user)
#
# @app.route("/post/<int:post_id>", methods=["GET","POST"])
# def show_post(post_id):
#     comment_form = CommentForm()
#     requested_post = BlogPost.query.get(post_id)
#     if comment_form.validate_on_submit():
#         new_comment = Comment(
#             text = comment_form.body.data
#         )
#         db.session.add(new_comment)
#         db.session.commit()
#
#     return render_template("post.html", post=requested_post, comment_form=comment_form)

###### post.author.name provides the name of the user that wrote the blog post - post is par

@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET","POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)

@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

if __name__ == "__main__":
    app.run(debug=True)
