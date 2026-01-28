import sys
import os

# Путь к вашему интерпретатору в venv
INTERP = os.path.expanduser("/var/www/u3375291/data/flaskenv/bin/python")
if sys.executable != INTERP:
   os.execl(INTERP, INTERP, *sys.argv)

sys.path.append(os.getcwd())

# Изменяем импорт: из файла app.py берем объект app и называем его application
from app import application

