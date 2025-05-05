from hashlib import sha256
from connect import G, N
import secrets
import json
import os


def load_chunks(s) -> bytes:
    header = s.recv(4)
    if not header:
        raise ConnectionError('Сервер не отправил заголовок!')

    length = int.from_bytes(header, 'big')
    response = b""

    while len(response) < length:
        chunk = s.recv(min(4096, length - len(response)))
        if not chunk:
            raise ConnectionError('Соединение прервано')
        response += chunk

    return response


def registration(s) -> None:

    username = input('Придумайте логин: ')
    password = input('Придумайте пароль: ')

    salt = os.urandom(32) # 32 байта, на сервер летит в hex

    x = int.from_bytes(sha256(salt + password.encode()).digest(), byteorder='big')
    v = pow(G, x, N)
    s.sendall(json.dumps({
        'login': username,
        'verify': v,
        'salt': bytes.hex(salt),
        'action': 'reg'
    }).encode())

    response = s.recv(4096).decode()
    data = json.loads(response)
    if data.get('status') == 'success':
        print(data.get('message'))
    else:
        print(data.get('error_message'))


def authencation(s) -> dict or bool:

    username = input('Введите свой логин: ')
    password = input('Введите свой пароль: ')

    print()

    a = secrets.randbelow(N - 1) + 1
    public_A = pow(G, a, N)

    s.sendall(json.dumps({
        'login': username,
        'public_A': public_A,
        'action': 'auth'
    }).encode())

    response = s.recv(4096)
    data = json.loads(response.decode())

    if data.get('status') == 'success':

        public_B = data.get('public_B')
        salt = bytes.fromhex(data.get('salt'))

        if public_B == 0:
            print('Ошибка: значение открытого ключа B равно нулю!')

        x = int.from_bytes(sha256(salt + password.encode()).digest(), byteorder='big')
        u = int.from_bytes(sha256(public_A.to_bytes((public_A.bit_length() + 7) // 8, 'big') + public_B.to_bytes((public_B.bit_length() + 7) // 8, 'big')).digest(), byteorder='big')
        k = int.from_bytes(
            sha256(N.to_bytes((N.bit_length() + 7) // 8, 'big') + G.to_bytes((G.bit_length() + 7) // 8, 'big')).digest(),
            byteorder='big')

        term = (public_B - k * pow(G, x, N)) % N
        Sc = pow(term, (a + u * x), N)

        M1 = int.from_bytes(sha256(public_A.to_bytes((public_A.bit_length() + 7) // 8, 'big') + public_B.to_bytes((public_B.bit_length() + 7) // 8, 'big') + Sc.to_bytes((Sc.bit_length() + 7) // 8, 'big')).digest(), byteorder='big')

        s.sendall(json.dumps({
            'M1': M1
        }).encode())

        response = json.loads(s.recv(4096).decode())

        if response.get('status') == 'success':
            print(response.get('message'))
            return {'username': username}
        else:
            print(response.get('error_message'))
            return False
    else:
        print(data.get('error_message'))


def create_post(s, username) -> None:

    text = input('Введите текст своего поста: ')

    s.sendall(json.dumps({
        'login': username,
        'text': text,
        'action': 'create_post'
    }).encode())

    response = s.recv(4096)
    data = json.loads(response.decode())

    if data.get('status') == 'success':
        print(data.get('message'))
    else:
        print(data.get('error_message'))


def view_my_posts(s, username, socket) -> None:

    s.sendall(json.dumps({
        'login': username,
        'action': 'view_my_posts'
    }).encode())

    s.settimeout(5.0)

    try:

        response = load_chunks(s)

        data = json.loads(response.decode())

        if data.get('status') == 'success':
            for post in data.get('posts'):
                print(f'{post["id"]}. {post["text"]} \nАвтор: {post["author"]}')
        else:
            print(data.get('error_message'))

    except socket.timeout:
        print("\nСервер не ответил вовремя..")


def view_user_posts(s, socket) -> None:

    username = input("\nВведите логин пользователя: ")

    s.sendall(json.dumps({
        'login': username,
        'action': 'view_user_posts'
    }).encode())

    s.settimeout(5.0)

    try:

        response = load_chunks(s)

        data = json.loads(response.decode())

        if data.get('status') == 'success':
            for post in data.get('posts'):
                print(f'{post["id"]}. {post["text"]} \nАвтор: {post["author"]}')
        else:
            print(data.get('error_message'))

    except socket.timeout:
        print("\nСервер не ответил вовремя..")


def delete_post(s, username, socket) -> None:

    post_id = input('\nВведите ID поста, который хотите удалить: ')

    s.sendall(json.dumps({
        'login': username,
        'post_id': post_id,
        'action': 'delete_post'
    }).encode())

    try:
        response = s.recv(4096)

        data = json.loads(response.decode())

        if data.get('status') == 'success':
            print(data.get('message'))
        else:
            print(data.get('error_message'))

    except socket.timeout:
        print("\nСервер не ответил вовремя..")
