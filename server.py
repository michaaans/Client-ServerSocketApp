from ServerHandlers.server_function import registration_handlers, authencation_handlers, create_post, view_my_posts, view_user_posts, delete_post
from connect import HOST, PORT, G, N, cursor, connect
from hashlib import sha256
import sqlite3
import secrets
import socket
import json


# таблица users
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    login TEXT PRIMARY KEY,
    verify TEXT,
    salt TEXT
)
''')

# включаем внешние ключи
cursor.execute("PRAGMA foreign_keys = ON")

# таблица posts
cursor.execute('''
CREATE TABLE IF NOT EXISTS posts (
    post_id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT NOT NULL,
    post_text TEXT NOT NULL,

    FOREIGN KEY (login) REFERENCES users(login) ON DELETE CASCADE
)
''')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f'Подключение на {addr}')
        while True:
            # принимаем и достаем данные от клиента
            data = conn.recv(4096).decode()
            if not data: break

            client_data = json.loads(data)

            action = client_data.get('action')

            if action == 'reg':
                registration_handlers(client_data, cursor, connect, conn, sqlite3, json)
            elif action == 'auth':
                authencation_handlers(client_data, cursor, conn, sqlite3, json, sha256, secrets, G, N)
            elif action == 'create_post':
                create_post(client_data, cursor, conn, connect, sqlite3, json)
            elif action == 'view_my_posts':
                view_my_posts(client_data, cursor, conn, json, sqlite3)
            elif action == 'view_user_posts':
                view_user_posts(client_data, cursor, conn, json, sqlite3)
            elif action == 'delete_post':
                delete_post(client_data, cursor, conn, sqlite3, json, connect)
connect.close()