# admin_manager.py
import sqlite3
import hashlib

DATABASE = 'bibliocase.db'

def make_admin(username):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('UPDATE users SET is_admin=1 WHERE username=?', (username,))
    
    if cursor.rowcount == 0:
        print(f"Пользователь {username} не найден")
    else:
        conn.commit()
        print(f"Пользователь {username} назначен администратором")
    
    conn.close()

# Использование: python admin_manager.py имя_пользователя