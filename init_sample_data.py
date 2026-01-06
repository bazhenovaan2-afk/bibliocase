"""
Скрипт для инициализации базы данных с тестовыми данными
Запустите этот скрипт один раз для создания примеров кейсов
"""

import sqlite3
import hashlib

DATABASE = 'bibliocase.db'

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_sample_data():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Создаем тестового пользователя
    try:
        cursor.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            ('demo_user', hash_password('demo123'))
        )
        user_id = cursor.lastrowid
        print(f"Создан тестовый пользователь: demo_user / demo123 (ID: {user_id})")
    except sqlite3.IntegrityError:
        cursor.execute('SELECT id FROM users WHERE username = ?', ('demo_user',))
        user = cursor.fetchone()
        user_id = user[0] if user else 1
        print(f"Пользователь demo_user уже существует (ID: {user_id})")
    
    # Примеры кейсов
    sample_cases = [
        {
            'title': 'Успешный запуск стартапа в сфере IT',
            'category': 'Бизнес',
            'content': '''Этот кейс описывает мой опыт запуска IT-стартапа. 

Основные вызовы:
- Поиск правильной ниши
- Формирование команды
- Привлечение первых клиентов

Уроки:
1. Важно начинать с малого и масштабироваться постепенно
2. Команда важнее идеи
3. Клиентский фидбек - это золото

Результат: За 6 месяцев мы достигли 100+ активных пользователей и получили первую прибыль.''',
            'user_id': user_id
        },
        {
            'title': 'Неудачный опыт в марафонском беге',
            'category': 'Спорт',
            'content': '''Отрицательный опыт, который многому меня научил.

Что произошло:
Я решил пробежать марафон без должной подготовки. Тренировался всего 2 месяца вместо рекомендуемых 4-6.

Проблемы:
- Травма колена на 25-м километре
- Сильное обезвоживание
- Не смог финишировать

Выводы:
1. Невозможно ускорить процесс подготовки
2. Важно слушать свое тело
3. Не стоит недооценивать важность правильной подготовки

Теперь я готовлюсь к следующему марафону более ответственно.''',
            'user_id': user_id
        },
        {
            'title': 'Внедрение системы управления проектами',
            'category': 'Технологии',
            'content': '''Кейс о внедрении новой системы управления проектами в компании.

Задача:
Перевести команду из 20 человек с Excel на профессиональную систему управления проектами.

Процесс:
1. Анализ потребностей команды
2. Выбор подходящего инструмента
3. Обучение сотрудников
4. Постепенное внедрение

Результаты:
- Увеличили продуктивность на 30%
- Сократили время на отчетность
- Улучшили коммуникацию в команде

Ключевые факторы успеха:
- Постепенное внедрение
- Обучение и поддержка
- Учет мнения команды''',
            'user_id': user_id
        }
    ]
    
    # Добавляем кейсы
    added = 0
    for case in sample_cases:
        try:
            cursor.execute(
                'INSERT INTO cases (title, category, content, user_id) VALUES (?, ?, ?, ?)',
                (case['title'], case['category'], case['content'], case['user_id'])
            )
            added += 1
        except Exception as e:
            print(f"Ошибка при добавлении кейса '{case['title']}': {e}")
    
    conn.commit()
    conn.close()
    
    print(f"\nДобавлено {added} тестовых кейсов")
    print("\nТеперь вы можете:")
    print("1. Войти как demo_user / demo123")
    print("2. Просмотреть созданные кейсы в коллекциях")
    print("3. Создать свои собственные кейсы")

if __name__ == '__main__':
    # Проверяем, что база данных существует
    try:
        conn = sqlite3.connect(DATABASE)
        conn.close()
        init_sample_data()
    except sqlite3.Error as e:
        print(f"Ошибка: База данных не найдена. Сначала запустите app.py для создания базы данных.")
        print(f"Детали: {e}")

