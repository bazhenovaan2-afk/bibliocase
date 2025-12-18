from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS
import sqlite3
import os
import hashlib
import secrets
from datetime import datetime
import base64

app = Flask(__name__)
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

def column_exists(cursor, table_name, column_name):
    """Проверить существование колонки в таблице"""
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = cursor.fetchall()
    return any(col[1] == column_name for col in columns)

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
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Миграция: добавляем is_admin если его нет
    if not column_exists(cursor, 'users', 'is_admin'):
        cursor.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0')
    
    # Таблица кейсов
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            image_path TEXT,
            content TEXT NOT NULL,
            user_id INTEGER,
            is_approved INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Миграция: добавляем is_approved если его нет
    if not column_exists(cursor, 'cases', 'is_approved'):
        cursor.execute('ALTER TABLE cases ADD COLUMN is_approved INTEGER DEFAULT 0')
        # Обновляем существующие кейсы - помечаем их как одобренные
        cursor.execute('UPDATE cases SET is_approved = 1 WHERE is_approved IS NULL OR is_approved = 0')
    
    # Таблица лайков
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            UNIQUE(case_id, user_id)
        )
    ''')
    
    # Создаем админский аккаунт, если его нет
    cursor.execute('SELECT id FROM users WHERE username = ?', ('admin',))
    admin_exists = cursor.fetchone()
    if not admin_exists:
        admin_password_hash = hash_password('admin123')
        cursor.execute(
            'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
            ('admin', admin_password_hash, 1)
        )
        print("Админский аккаунт создан: admin / admin123")
    
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
        'SELECT id, username, is_admin FROM users WHERE username = ? AND password_hash = ?',
        (username, password_hash)
    )
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'message': 'Вход выполнен успешно',
            'user_id': user['id'],
            'username': user['username'],
            'is_admin': bool(user['is_admin'])
        }), 200
    else:
        return jsonify({'error': 'Неверное имя пользователя или пароль'}), 401

@app.route('/api/cases', methods=['GET'])
def get_cases():
    """Получить все кейсы с фильтрацией"""
    category = request.args.get('category')
    search = request.args.get('search')
    user_id = request.args.get('user_id')  # Для проверки лайков
    show_pending = request.args.get('show_pending') == 'true'  # Для админа
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Проверяем, является ли пользователь админом
    is_admin = False
    if user_id:
        cursor.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if user:
            is_admin = bool(user['is_admin'])
    
    query = '''SELECT c.*, u.username, 
               COUNT(DISTINCT l.id) as likes_count,
               CASE WHEN ? > 0 AND EXISTS(SELECT 1 FROM likes WHERE case_id = c.id AND user_id = ?) THEN 1 ELSE 0 END as is_liked
               FROM cases c 
               LEFT JOIN users u ON c.user_id = u.id 
               LEFT JOIN likes l ON c.id = l.case_id
               WHERE 1=1'''
    params = [int(user_id) if user_id else 0, int(user_id) if user_id else 0]
    
    # Показываем только одобренные кейсы, если не админ и не запрошены pending
    if not is_admin and not show_pending:
        query += ' AND c.is_approved = 1'
    
    if category:
        query += ' AND c.category = ?'
        params.append(category)
    
    if search:
        query += ' AND (c.title LIKE ? OR c.content LIKE ?)'
        search_term = f'%{search}%'
        params.extend([search_term, search_term])
    
    query += ' GROUP BY c.id ORDER BY c.created_at DESC'
    
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
            'created_at': case['created_at'],
            'likes_count': case['likes_count'] or 0,
            'is_liked': bool(case['is_liked']),
            'is_approved': bool(case['is_approved'])
        }
        result.append(case_dict)
    
    return jsonify(result), 200

@app.route('/api/cases/<int:case_id>', methods=['GET'])
def get_case(case_id):
    """Получить конкретный кейс"""
    user_id = request.args.get('user_id')
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Проверяем, является ли пользователь админом
    is_admin = False
    if user_id:
        cursor.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if user:
            is_admin = bool(user['is_admin'])
    
    query = '''SELECT c.*, u.username,
               COUNT(DISTINCT l.id) as likes_count,
               CASE WHEN ? > 0 AND EXISTS(SELECT 1 FROM likes WHERE case_id = c.id AND user_id = ?) THEN 1 ELSE 0 END as is_liked
               FROM cases c 
               LEFT JOIN users u ON c.user_id = u.id 
               LEFT JOIN likes l ON c.id = l.case_id
               WHERE c.id = ?'''
    
    params = [int(user_id) if user_id else 0, int(user_id) if user_id else 0, case_id]
    
    # Если не админ, показываем только одобренные кейсы
    if not is_admin:
        query += ' AND c.is_approved = 1'
    
    query += ' GROUP BY c.id'
    
    cursor.execute(query, params)
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
            'created_at': case['created_at'],
            'likes_count': case['likes_count'] or 0,
            'is_liked': bool(case['is_liked'])
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
    
    # Новые кейсы создаются с is_approved = 0 (на модерации)
    cursor.execute(
        'INSERT INTO cases (title, category, content, image_path, user_id, is_approved) VALUES (?, ?, ?, ?, ?, 0)',
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
    
    # Считаем только одобренные кейсы
    cursor.execute('SELECT COUNT(*) as count FROM cases WHERE is_approved = 1')
    cases_count = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(*) as count FROM users')
    users_count = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(DISTINCT category) as count FROM cases WHERE is_approved = 1')
    categories_count = cursor.fetchone()['count']
    
    conn.close()
    
    return jsonify({
        'cases': cases_count,
        'users': users_count,
        'categories': categories_count
    }), 200

@app.route('/api/pending-cases', methods=['GET'])
def get_pending_cases():
    """Получить кейсы на модерации (только для админа)"""
    user_id = request.args.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'Требуется авторизация'}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Проверяем, является ли пользователь админом
    cursor.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    if not user or not user['is_admin']:
        conn.close()
        return jsonify({'error': 'Доступ запрещен'}), 403
    
    # Получаем неодобренные кейсы
    cursor.execute('''
        SELECT c.*, u.username,
        COUNT(DISTINCT l.id) as likes_count
        FROM cases c
        LEFT JOIN users u ON c.user_id = u.id
        LEFT JOIN likes l ON c.id = l.case_id
        WHERE c.is_approved = 0
        GROUP BY c.id
        ORDER BY c.created_at DESC
    ''')
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
            'created_at': case['created_at'],
            'likes_count': case['likes_count'] or 0
        }
        result.append(case_dict)
    
    return jsonify(result), 200

@app.route('/api/cases/<int:case_id>/approve', methods=['POST'])
def approve_case(case_id):
    """Одобрить кейс (только для админа)"""
    data = request.json
    user_id = data.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'Требуется авторизация'}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Проверяем, является ли пользователь админом
    cursor.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    if not user or not user['is_admin']:
        conn.close()
        return jsonify({'error': 'Доступ запрещен'}), 403
    
    # Одобряем кейс
    cursor.execute('UPDATE cases SET is_approved = 1 WHERE id = ?', (case_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Кейс одобрен'}), 200

@app.route('/api/cases/<int:case_id>/reject', methods=['POST'])
def reject_case(case_id):
    """Отклонить кейс (только для админа)"""
    data = request.json
    user_id = data.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'Требуется авторизация'}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Проверяем, является ли пользователь админом
    cursor.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    if not user or not user['is_admin']:
        conn.close()
        return jsonify({'error': 'Доступ запрещен'}), 403
    
    # Удаляем кейс
    cursor.execute('DELETE FROM cases WHERE id = ?', (case_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Кейс отклонен'}), 200

@app.route('/api/cases/<int:case_id>/like', methods=['POST'])
def toggle_like(case_id):
    """Поставить или убрать лайк с кейса"""
    data = request.json
    user_id = data.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'Требуется авторизация'}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Проверяем, есть ли уже лайк
    cursor.execute(
        'SELECT id FROM likes WHERE case_id = ? AND user_id = ?',
        (case_id, user_id)
    )
    existing_like = cursor.fetchone()
    
    if existing_like:
        # Убираем лайк
        cursor.execute(
            'DELETE FROM likes WHERE case_id = ? AND user_id = ?',
            (case_id, user_id)
        )
        action = 'removed'
    else:
        # Ставим лайк
        cursor.execute(
            'INSERT INTO likes (case_id, user_id) VALUES (?, ?)',
            (case_id, user_id)
        )
        action = 'added'
    
    conn.commit()
    
    # Получаем новое количество лайков
    cursor.execute('SELECT COUNT(*) as count FROM likes WHERE case_id = ?', (case_id,))
    likes_count = cursor.fetchone()['count']
    
    conn.close()
    
    return jsonify({
        'action': action,
        'likes_count': likes_count,
        'is_liked': action == 'added'
    }), 200

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Отдать загруженный файл"""
    return send_from_directory(UPLOAD_FOLDER, filename)

# HTML Routes
@app.route('/')
def index():
    """Главная страница"""
    return render_template('main.html')

@app.route('/collections')
def collections():
    """Страница коллекций"""
    return render_template('collections.html')

@app.route('/create-case')
def create_case_page():
    """Страница создания кейса"""
    return render_template('create-case.html')

@app.route('/login')
def login_page():
    """Страница входа"""
    return render_template('login.html')

@app.route('/signup')
def signup_page():
    """Страница регистрации"""
    return render_template('signup.html')

@app.route('/case/<int:case_id>')
def case_detail(case_id):
    """Страница просмотра кейса"""
    return render_template('case-detail.html')

@app.route('/admin/moderate')
def admin_moderate():
    """Страница модерации для админа"""
    return render_template('admin-moderate.html')

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)

