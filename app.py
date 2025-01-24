from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
from functools import wraps
import os
import hashlib
import hmac
import time
from urllib.parse import parse_qsl

app = Flask(__name__)
app.secret_key = os.urandom(24)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

ADMIN_ID = 6336204836
BOT_TOKEN = "YOUR_BOT_TOKEN"  # Замените на ваш токен бота
BOT_USERNAME = "banangoldmarketbot"  # Добавляем имя бота

class User(UserMixin):
    def __init__(self, id, username, balance, gold, is_admin=False):
        self.id = id
        self.username = username
        self.balance = balance
        self.gold = gold
        self.is_admin = is_admin

def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user_data = cur.fetchone()
    conn.close()
    if user_data:
        return User(
            id=user_data['id'],
            username=user_data['name'],
            balance=user_data['balance'],
            gold=user_data['gold'],
            is_admin=user_data['id'] == ADMIN_ID
        )
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Доступ запрещен')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def verify_telegram_data(data):
    if 'hash' not in data:
        return False

    auth_data = data.copy()
    auth_hash = auth_data.pop('hash')
    data_check_string = '\n'.join(f'{k}={v}' for k, v in sorted(auth_data.items()))
    
    secret_key = hashlib.sha256(BOT_TOKEN.encode()).digest()
    hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    
    return hash == auth_hash

@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('dashboard.html')
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        auth_data = {key: request.form[key] for key in request.form}
        if not verify_telegram_data(auth_data):
            flash('Ошибка аутентификации')
            return redirect(url_for('login'))

        telegram_id = int(auth_data['id'])
        username = auth_data.get('username', '')

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE id = ?', (telegram_id,))
        user_data = cur.fetchone()
        conn.close()

        if user_data:
            user = User(
                id=user_data['id'],
                username=user_data['name'],
                balance=user_data['balance'],
                gold=user_data['gold'],
                is_admin=user_data['id'] == ADMIN_ID
            )
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Пользователь не найден')
            return redirect(url_for('login'))

    return render_template('login.html', bot_username=BOT_USERNAME)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Остальные маршруты остаются без изменений...

if __name__ == '__main__':
    app.run(debug=True)