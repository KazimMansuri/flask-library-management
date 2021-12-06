from flask import Flask, render_template, redirect, url_for, session, flash
from flask.globals import request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, DateTimeField
from wtforms.fields.core import SelectField
from wtforms.fields.simple import TextField
from wtforms.validators import InputRequired, Email, Length, ValidationError, DataRequired, EqualTo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'c1155c6a351e49eba15c00ce577b259e'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:''@localhost/library'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

############################################################################################
# Model :-

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_name = db.Column(db.String(15), unique=True)
    book_description = db.Column(db.String(25))
    category = db.Column(db.String(20))
    book_type = db.Column(db.String(20), nullable=False)
    price = db.Column(db.String(20), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


    def __repr__(self):
        return f"Post('{self.book_name}', '{self.date_posted}')"



#########################################################################################
# Forms :-


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "example@gmail.com"})
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')],  render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField("Sign Up")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one.")

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("That email address belongs to different user. Please choose a different one.")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField("Password", validators=[InputRequired(), Length(max=50)], render_kw={"placeholder":  "Password"})
    submit = SubmitField("Login")


class BookForm(FlaskForm):
    book_name = StringField("Book Name", validators=[InputRequired(), Length(max=200)], render_kw={"placeholder": "Title"})
    book_description = TextField("Book description", validators=[Length(max=5000)], render_kw={"placeholder":  "description"})
    category = SelectField("Book Category",choices= [('Ebook', 'Ebook'),('Hardcopy', 'Hardcopy')], validators=[DataRequired()])
    book_type = SelectField("Book Type",choices= [('sports', 'sports'),('educational', 'educational'),('motivational', 'motivational')], validators=[DataRequired()])
    price = StringField("Price", validators=[InputRequired(), Length(max=25)], render_kw={"placeholder": "Price"})
    submit = SubmitField("Add Book")


############################################################################################
# Routes :-

@app.route('/home')
@app.route('/')
@login_required
def Index():
    return render_template('index.html', title='Home')


@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("Index"))
    
        flash("User does not exist, or invalid username or password.")
    return render_template('auth/login.html', title="Login", form=form)


@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("User Registered successfully..!")
        
        return redirect(url_for('login'))
    return render_template('auth/register.html', title='Register', form=form)


@app.route('/logout', methods=["GET","POST"])
def logout():
    session.clear()
    logout_user()
    return redirect(url_for('login'))


@app.route('/createbook', methods=['GET','POST'])
@login_required
def CreateBook():
    form = BookForm()
    if form.validate_on_submit():
        new_book = Book(book_name=form.book_name.data,book_description=form.book_description.data,category=form.category.data,book_type=form.book_type.data,price=form.price.data)
        db.session.add(new_book)
        db.session.commit()
        return redirect(url_for('Books_list'))
    return render_template('book_form.html', form=form)


@app.route('/books', methods=['GET','POST'])
def Books_list():
    books = Book.query.all()
    return render_template('book_list.html', books=books)



@app.route('/book_detail/<int:id>', methods=['GET','POST'])
@login_required
def Books_detail(id):
    book = Book.query.filter_by(id=id).first()
    return render_template('book_detail.html', book=book)



@app.route('/book/<int:id>/update', methods=['GET','POST'])
@login_required
def Book_Update(id):
    print("method ", request.method)
    book = Book.query.filter_by(id=id).first()
    form = BookForm(obj=book)
    if form.validate_on_submit():
        
        book.book_name = form.book_name.data
        book.book_description = form.book_description.data
        book.category = form.category.data
        book.book_type = form.book_type.data
        book.price = form.price.data
        
        db.session.add(book)
        db.session.commit()
        return redirect(url_for('Books_list'))

    return render_template('book_update.html', book=book, form=form)




@app.route('/deletebook/<int:id>', methods=['GET',"POST"])
def Book_Delete(id):
    book = Book.query.get_or_404(id)

    db.session.delete(book)
    db.session.commit()
    return redirect(url_for('Books_list'))



########################################################################################    

if __name__ == '__main__':
    app.run(debug=True)
