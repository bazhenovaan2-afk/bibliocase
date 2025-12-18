from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
import os
import hashlib
import secrets
from datetime import datetime
import base64

app = Flask(__name__, static_folder='Website', static_url_path='')
CORS(app)

# Конфигурация
DATABASE = 'bibliocase.db'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Создаем папку для загрузок
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_db():
    """Получить соединение с базой данных"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Инициализировать базу данных"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Таблица пользователей
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Таблица кейсов
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            image_path TEXT,
            content TEXT NOT NULL,
            user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def hash_password(password):
    """Хешировать пароль"""
    return hashlib.sha256(password.encode()).hexdigest()

def allowed_file(filename):
    """Проверить разрешенное расширение файла"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# API Endpoints

@app.route('/api/register', methods=['POST'])
def register():
    """Регистрация нового пользователя"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Имя пользователя и пароль обязательны'}), 400
    
    if len(password) < 6:
        return jsonify({'error': 'Пароль должен содержать минимум 6 символов'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        password_hash = hash_password(password)
        cursor.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            (username, password_hash)
        )
        conn.commit()
        user_id = cursor.lastrowid
        return jsonify({
            'message': 'Регистрация успешна',
            'user_id': user_id,
            'username': username
        }), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Пользователь с таким именем уже существует'}), 400
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    """Вход пользователя"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Имя пользователя и пароль обязательны'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    password_hash = hash_password(password)
    
    cursor.execute(
        'SELECT id, username FROM users WHERE username = ? AND password_hash = ?',
        (username, password_hash)
    )
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'message': 'Вход выполнен успешно',
            'user_id': user['id'],
            'username': user['username']
        }), 200
    else:
        return jsonify({'error': 'Неверное имя пользователя или пароль'}), 401

@app.route('/api/cases', methods=['GET'])
def get_cases():
    """Получить все кейсы с фильтрацией"""
    category = request.args.get('category')
    search = request.args.get('search')
    
    conn = get_db()
    cursor = conn.cursor()
    
    query = 'SELECT c.*, u.username FROM cases c LEFT JOIN users u ON c.user_id = u.id WHERE 1=1'
    params = []
    
    if category:
        query += ' AND c.category = ?'
        params.append(category)
    
    if search:
        query += ' AND (c.title LIKE ? OR c.content LIKE ?)'
        search_term = f'%{search}%'
        params.extend([search_term, search_term])
    
    query += ' ORDER BY c.created_at DESC'
    
    cursor.execute(query, params)
    cases = cursor.fetchall()
    conn.close()
    
    result = []
    for case in cases:
        case_dict = {
            'id': case['id'],
            'title': case['title'],
            'category': case['category'],
            'content': case['content'],
            'image_path': case['image_path'],
            'username': case['username'],
            'created_at': case['created_at']
        }
        result.append(case_dict)
    
    return jsonify(result), 200

@app.route('/api/cases/<int:case_id>', methods=['GET'])
def get_case(case_id):
    """Получить конкретный кейс"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute(
        'SELECT c.*, u.username FROM cases c LEFT JOIN users u ON c.user_id = u.id WHERE c.id = ?',
        (case_id,)
    )
    case = cursor.fetchone()
    conn.close()
    
    if case:
        return jsonify({
            'id': case['id'],
            'title': case['title'],
            'category': case['category'],
            'content': case['content'],
            'image_path': case['image_path'],
            'username': case['username'],
            'created_at': case['created_at']
        }), 200
    else:
        return jsonify({'error': 'Кейс не найден'}), 404

@app.route('/api/cases', methods=['POST'])
def create_case():
    """Создать новый кейс"""
    data = request.json
    title = data.get('title')
    category = data.get('category')
    content = data.get('content')
    image_data = data.get('image')  # base64 encoded image
    user_id = data.get('user_id')
    
    if not title or not category or not content:
        return jsonify({'error': 'Название, категория и текст обязательны'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    image_path = None
    if image_data:
        try:
            # Декодируем base64 изображение
            image_format, image_str = image_data.split(';base64,')
            ext = image_format.split('/')[-1]
            if ext not in ALLOWED_EXTENSIONS:
                ext = 'png'
            
            image_bytes = base64.b64decode(image_str)
            filename = f"{secrets.token_hex(8)}.{ext}"
            image_path = os.path.join(UPLOAD_FOLDER, filename)
            
            with open(image_path, 'wb') as f:
                f.write(image_bytes)
            
            image_path = f"/uploads/{filename}"
        except Exception as e:
            return jsonify({'error': f'Ошибка загрузки изображения: {str(e)}'}), 400
    
    cursor.execute(
        'INSERT INTO cases (title, category, content, image_path, user_id) VALUES (?, ?, ?, ?, ?)',
        (title, category, content, image_path, user_id)
    )
    conn.commit()
    case_id = cursor.lastrowid
    conn.close()
    
    return jsonify({
        'message': 'Кейс создан успешно',
        'case_id': case_id
    }), 201

@app.route('/api/categories', methods=['GET'])
def get_categories():
    """Получить список всех категорий"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT DISTINCT category FROM cases ORDER BY category')
    categories = cursor.fetchall()
    conn.close()
    
    result = [cat['category'] for cat in categories]
    return jsonify(result), 200

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Получить статистику"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) as count FROM cases')
    cases_count = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(*) as count FROM users')
    users_count = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(DISTINCT category) as count FROM cases')
    categories_count = cursor.fetchone()['count']
    
    conn.close()
    
    return jsonify({
        'cases': cases_count,
        'users': users_count,
        'categories': categories_count
    }), 200

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Отдать загруженный файл"""
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/')
def index():
    """Главная страница"""
    return send_from_directory('Website', 'main.html')

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)

