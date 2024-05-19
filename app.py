from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import bcrypt
import sqlite3
from functools import wraps
import scrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yoursecretkey'
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    return f'Hello, {session["username"]}!'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        if cursor.fetchone() is not None:
            return 'User already exists'
        salt = bcrypt.gensalt()   # Генерация соли
        hashed_password_salt = scrypt.hash(password.encode('utf-8'), salt) # Функция H = scrypt(password, salt)
        cursor.execute('INSERT INTO users (username, salt, hashed_password_salt) VALUES (?, ?, ?)', (username, salt, hashed_password_salt))
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        if user is None:
            return 'Invalid username or password'
        salt = user['salt'] # Соль из БД
        challenge = bcrypt.gensalt() # Генерация challenge
        # Вычисление Hs = hash(H, challenge) пользователем
        hashed_password_salt = scrypt.hash(password.encode('utf-8'), salt)
        hashed_password_client = bcrypt.hashpw(hashed_password_salt, challenge)
        # Вычисление Hs = hash(H, challenge) сервером
        hashed_password_server = bcrypt.hashpw(user['hashed_password_salt'], challenge)
        if hashed_password_client == hashed_password_server:
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return 'Invalid username or password'
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
