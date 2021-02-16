from flask import Flask, render_template, flash, redirect, logging, url_for, session, request
from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)

#Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '123456'
app.config['MYSQL_DB'] = 'myflaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# init MySQL
mysql = MySQL(app)

Articles = Articles()

@app.route('/')
def index():
  return render_template('home.html')

@app.route('/about')
def about():
  return render_template('about.html')

@app.route('/articles')
def articles():
  return render_template('articles.html', articles=Articles)

@app.route('/article/<string:id>/')
def article(id):
  return render_template('article.html', id=id)

class RegisterForm(Form):
  name = StringField('Name', [validators.Length(min=1, max=50)])
  username = StringField('Username', [validators.Length(min=4, max=25)])
  email = StringField('Email', [validators.Length(min=6, max=50)])
  password = PasswordField('Password', [
    validators.DataRequired(),
    validators.EqualTo('confirm', message='Passwords do not match')
  ])
  confirm = PasswordField('Confirm Password')

@app.route('/register', methods=['GET', 'POST'])
def register():
  form = RegisterForm(request.form)
  if request.method == 'POST' and form.validate():
    name = form.name.data
    email = form.email.data
    username = form.username.data
    password = sha256_crypt.encrypt(str(form.password.data))

    # create cursor
    cur = mysql.connection.cursor()

    cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s,%s,%s,%s)", (name, email, username, password))

    # commit to DB
    mysql.connection.commit()

    #close connection
    cur.close()

    flash('Registration successful, proceed to log in', 'success')

    return redirect(url_for('index'))
    
  return render_template('register.html', form=form)


#login user
@app.route('/login', methods=['GET', 'POST'])
def login():
  if request.method == 'POST':
    # Get form fields
    username = request.form['username']
    password_candidate = request.form['password']

    # Create cursor
    cur = mysql.connection.cursor()
    
    # Get user by username
    result = cur.execute("SELECT * FROM users WHERE username = %s", [username])
    if result > 0:
      #Get stored hash
      data = cur.fetchone()
      password = data['password']

      # Compare passwords
      if sha256_crypt.verify(password_candidate, password):
        session['logged_in'] = True
        session['username'] = username

        flash('Login Successful. Happy Writing!', 'success')

        return redirect(url_for('dashboard'))
      else:
        error = 'Invalid password'
        return render_template('login.html', error=error)
    else:
      error = 'User not found'
      return render_template('login.html', error=error)
  return render_template('login.html')

# Protect routes: check if user is logged in
def login_required(f):
  @wraps(f)
  def decorated_function(*args, **kwargs):
    if 'logged_in' in session:
      return f(*args, **kwargs)
    else:
      flash('Access denied. Please Log in to continue', 'danger')
      return redirect(url_for('login'))
  return decorated_function

# Logout
@app.route('/logout')
def logout():
  session.clear()
  flash('Logout successful.', 'success')
  return redirect(url_for('login'))

# Dashboard 
@app.route('/dashboard')
@login_required
def dashboard():
  return render_template('dashboard.html')



if __name__ == '__main__':
  app.secret_key='kiratu321'
  app.run(debug = True)
