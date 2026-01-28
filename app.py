from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS
import sqlite3
import os
import hashlib
import secrets
import base64
import io
from PIL import Image  # Импортируем библиотеку для работы с изображениями

application = Flask(__name__)
CORS(application)

# Конфигурация
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
DATABASE = os.path.join(BASE_DIR, 'bibliocase.db')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
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
    
    try:
        cursor.execute('SELECT id FROM users WHERE username = ?', ('admin',))
        if not cursor.fetchone():
            admin_pass = hashlib.sha256('admin123'.encode()).hexdigest()
            cursor.execute('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)', 
                           ('admin', admin_pass))
    except Exception as e:
        print(f"Ошибка создания админа: {e}")

    conn.commit()
    conn.close()

def get_safe_user_id(req_args):
    raw_id = req_args.get('user_id')
    if not raw_id or raw_id == 'undefined' or raw_id == 'null':
        return 0
    try:
        return int(raw_id)
    except (ValueError, TypeError):
        return 0

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# API Endpoints

@application.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Заполните все поля'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Пароль должен быть не менее 6 символов'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        pwd_hash = hash_password(password)
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, pwd_hash))
        conn.commit()
        uid = cursor.lastrowid
        return jsonify({'message': 'OK', 'user_id': uid, 'username': username}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Пользователь уже существует'}), 400
    finally:
        conn.close()

@application.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    conn = get_db()
    cursor = conn.cursor()
    pwd_hash = hash_password(password)
    cursor.execute('SELECT id, username, is_admin FROM users WHERE username=? AND password_hash=?', (username, pwd_hash))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({'message': 'OK', 'user_id': user['id'], 'username': user['username'], 'is_admin': bool(user['is_admin'])}), 200
    return jsonify({'error': 'Неверные данные'}), 401

@application.route('/api/cases', methods=['GET'])
def get_cases():
    user_id = get_safe_user_id(request.args)
    category = request.args.get('category')
    search = request.args.get('search')
    show_pending = request.args.get('show_pending') == 'true'

    conn = get_db()
    cursor = conn.cursor()

    is_admin = False
    if user_id:
        cursor.execute('SELECT is_admin FROM users WHERE id=?', (user_id,))
        u = cursor.fetchone()
        if u: is_admin = bool(u['is_admin'])

    query = '''SELECT c.*, u.username, 
               COUNT(DISTINCT l.id) as likes_count,
               CASE WHEN ? > 0 AND EXISTS(SELECT 1 FROM likes WHERE case_id = c.id AND user_id = ?) THEN 1 ELSE 0 END as is_liked
               FROM cases c 
               LEFT JOIN users u ON c.user_id = u.id 
               LEFT JOIN likes l ON c.id = l.case_id
               WHERE 1=1'''
    params = [user_id, user_id]

    if not is_admin and not show_pending:
        query += ' AND c.is_approved = 1'
    
    if category:
        query += ' AND c.category = ?'
        params.append(category)
    
    if search:
        query += ' AND (c.title LIKE ? OR c.content LIKE ?)'
        st = f'%{search}%'
        params.extend([st, st])
    
    query += ' GROUP BY c.id ORDER BY c.created_at DESC'
    
    try:
        cursor.execute(query, params)
        cases = cursor.fetchall()
    except sqlite3.OperationalError:
        conn.close()
        init_db()
        return get_cases()

    conn.close()
    
    result = []
    for c in cases:
        result.append({
            'id': c['id'], 'title': c['title'], 'category': c['category'],
            'content': c['content'], 'image_path': c['image_path'],
            'username': c['username'], 'created_at': c['created_at'],
            'likes_count': c['likes_count'], 'is_liked': bool(c['is_liked']),
            'is_approved': bool(c['is_approved'])
        })
    return jsonify(result), 200

@application.route('/api/cases/<int:case_id>', methods=['GET'])
def get_case(case_id):
    user_id = get_safe_user_id(request.args)
    conn = get_db()
    cursor = conn.cursor()
    
    is_admin = False
    if user_id:
        cursor.execute('SELECT is_admin FROM users WHERE id=?', (user_id,))
        u = cursor.fetchone()
        if u: is_admin = bool(u['is_admin'])

    query = '''SELECT c.*, u.username,
               COUNT(DISTINCT l.id) as likes_count,
               CASE WHEN ? > 0 AND EXISTS(SELECT 1 FROM likes WHERE case_id = c.id AND user_id = ?) THEN 1 ELSE 0 END as is_liked
               FROM cases c 
               LEFT JOIN users u ON c.user_id = u.id 
               LEFT JOIN likes l ON c.id = l.case_id
               WHERE c.id = ?'''
    params = [user_id, user_id, case_id]
    
    if not is_admin:
        query += ' AND c.is_approved = 1'
        
    query += ' GROUP BY c.id'
    
    cursor.execute(query, params)
    case = cursor.fetchone()
    conn.close()
    
    if case:
        return jsonify({
            'id': case['id'], 'title': case['title'], 'category': case['category'],
            'content': case['content'], 'image_path': case['image_path'],
            'username': case['username'], 'created_at': case['created_at'],
            'likes_count': case['likes_count'], 'is_liked': bool(case['is_liked'])
        })
    return jsonify({'error': 'Not found'}), 404

@application.route('/api/cases', methods=['POST'])
def create_case():
    data = request.json
    try:
        image_path = None
        if data.get('image'):
            # --- ЛОГИКА ОБРАБОТКИ И СЖАТИЯ КАРТИНКИ ---
            header, imgstr = data['image'].split(';base64,')
            ext = header.split('/')[-1]
            
            if ext not in ALLOWED_EXTENSIONS:
                ext = 'png' # Fallback
                
            # Декодируем
            image_bytes = base64.b64decode(imgstr)
            
            # Открываем через Pillow
            img = Image.open(io.BytesIO(image_bytes))
            
            # Конвертируем в RGB если это PNG с прозрачностью или RGBA, чтобы сохранить как JPG (опционально)
            # Но лучше оставим формат оригинала, просто уменьшим размер.
            
            # Максимальный размер (ширина или высота)
            MAX_SIZE = (800, 800)
            img.thumbnail(MAX_SIZE, Image.Resampling.LANCZOS)
            
            # Генерируем имя
            fname = f"{secrets.token_hex(8)}.{ext}"
            full_path = os.path.join(UPLOAD_FOLDER, fname)
            
            # Сохраняем
            img.save(full_path)
            image_path = f"/static/uploads/{fname}"
            # -------------------------------------------

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO cases (title, category, content, image_path, user_id, is_approved) VALUES (?,?,?,?,?,0)',
                       (data['title'], data['category'], data['content'], image_path, data['user_id']))
        conn.commit()
        cid = cursor.lastrowid
        conn.close()
        return jsonify({'message': 'OK', 'case_id': cid}), 201
    except Exception as e:
        print(f"Error creating case: {e}")
        return jsonify({'error': str(e)}), 400

@application.route('/api/categories', methods=['GET'])
def get_categories():
    conn = get_db()
    curr = conn.cursor()
    try:
        curr.execute('SELECT DISTINCT category FROM cases ORDER BY category')
        cats = [r[0] for r in curr.fetchall()]
    except:
        cats = []
    conn.close()
    return jsonify(cats), 200

@application.route('/api/stats', methods=['GET'])
def get_stats():
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute('SELECT COUNT(*) as c FROM cases WHERE is_approved=1')
        cc = cur.fetchone()['c']
        cur.execute('SELECT COUNT(*) as c FROM users')
        uc = cur.fetchone()['c']
        cur.execute('SELECT COUNT(DISTINCT category) as c FROM cases WHERE is_approved=1')
        catc = cur.fetchone()['c']
        return jsonify({'cases': cc, 'users': uc, 'categories': catc})
    except sqlite3.OperationalError:
        init_db()
        return jsonify({'cases': 0, 'users': 1, 'categories': 0})
    finally:
        conn.close()

@application.route('/api/pending-cases', methods=['GET'])
def get_pending():
    user_id = get_safe_user_id(request.args)
    if not user_id: return jsonify({'error': 'Auth required'}), 401
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT is_admin FROM users WHERE id=?', (user_id,))
    u = cur.fetchone()
    if not u or not u['is_admin']:
        conn.close()
        return jsonify({'error': 'Forbidden'}), 403
        
    cur.execute('''SELECT c.*, u.username, COUNT(DISTINCT l.id) as likes_count 
                   FROM cases c LEFT JOIN users u ON c.user_id=u.id 
                   LEFT JOIN likes l ON c.id=l.case_id 
                   WHERE c.is_approved=0 GROUP BY c.id ORDER BY c.created_at DESC''')
    res = []
    for c in cur.fetchall():
        res.append({
            'id': c['id'], 'title': c['title'], 'category': c['category'],
            'content': c['content'], 'image_path': c['image_path'],
            'username': c['username'], 'created_at': c['created_at'],
            'likes_count': c['likes_count']
        })
    conn.close()
    return jsonify(res), 200

@application.route('/api/cases/<int:case_id>/approve', methods=['POST'])
def approve(case_id):
    user_id = request.json.get('user_id')
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT is_admin FROM users WHERE id=?', (user_id,))
    u = cur.fetchone()
    if u and u['is_admin']:
        cur.execute('UPDATE cases SET is_approved=1 WHERE id=?', (case_id,))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Approved'}), 200
    conn.close()
    return jsonify({'error': 'Forbidden'}), 403

@application.route('/api/cases/<int:case_id>/reject', methods=['POST'])
def reject(case_id):
    user_id = request.json.get('user_id')
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT is_admin FROM users WHERE id=?', (user_id,))
    u = cur.fetchone()
    if u and u['is_admin']:
        cur.execute('DELETE FROM cases WHERE id=?', (case_id,))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Rejected'}), 200
    conn.close()
    return jsonify({'error': 'Forbidden'}), 403

@application.route('/api/cases/<int:case_id>/like', methods=['POST'])
def like(case_id):
    user_id = request.json.get('user_id')
    if not user_id: return jsonify({'error': 'Auth required'}), 401
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT id FROM likes WHERE case_id=? AND user_id=?', (case_id, user_id))
    if cur.fetchone():
        cur.execute('DELETE FROM likes WHERE case_id=? AND user_id=?', (case_id, user_id))
        act = 'removed'
    else:
        cur.execute('INSERT INTO likes (case_id, user_id) VALUES (?,?)', (case_id, user_id))
        act = 'added'
    conn.commit()
    cur.execute('SELECT COUNT(*) as c FROM likes WHERE case_id=?', (case_id,))
    cnt = cur.fetchone()['c']
    conn.close()
    return jsonify({'action': act, 'likes_count': cnt, 'is_liked': act=='added'})

@application.route('/static/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@application.route('/')
def index(): return render_template('main.html')

@application.route('/collections')
def collections(): return render_template('collections.html')

@application.route('/create-case')
def create_case_page(): return render_template('create-case.html')

@application.route('/login')
def login_page(): return render_template('login.html')

@application.route('/signup')
def signup_page(): return render_template('signup.html')

@application.route('/case/<int:case_id>')
def case_detail(case_id): return render_template('case-detail.html')

@application.route('/admin/moderate')
def admin_moderate(): return render_template('admin-moderate.html')

if __name__ == '__main__':
    init_db()
    application.run(host='0.0.0.0', port=5000)