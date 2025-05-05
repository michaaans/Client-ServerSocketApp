

def registration_handlers(client_data, cursor, connect, conn, sqlite3, json):
    username = client_data.get('login')
    verify = str(client_data.get('verify'))
    salt = client_data.get('salt')  # в hex

    try:
        cursor.execute('''INSERT INTO users (login, verify, salt) VALUES (?, ?, ?)''', (username, verify, salt))
        connect.commit()

        conn.sendall(json.dumps({
            'status': 'success',
            'message': f'\nПользователь {username} успешно зарегистрирован!'
        }).encode())

    except sqlite3.Error as e:
        conn.sendall(json.dumps({
            'status': 'error',
            'error_message': f'\nОшибка базы данных: {e}'
        }).encode())


def authencation_handlers(client_data, cursor, conn, sqlite3, json, sha256, secrets, G, N):

    username = client_data.get('login')
    public_A = client_data.get('public_A')

    if public_A == 0:
        # conn.sendall('Ошибка: значение A равно нулю!'.encode())
        conn.sendall(json.dumps({
            'status': 'error',
            'error_message': '\nОшибка: значение открытого ключа A равно нулю!'
        }).encode())

    try:
        cursor.execute('''SELECT verify, salt FROM users WHERE login = ?''', (username,))

        record = cursor.fetchone()

        if record is None:
            # print(f'Пользователь {username} не найден!')
            conn.sendall(json.dumps({
                'status': 'error',
                'error_message': f'\nОшибка: Пользователь {username} не найден!'
            }).encode())
            verify, salt = None, None
        else:
            verify, salt = record[0], record[1]
            b = secrets.randbelow(N - 1) + 1
            k = int.from_bytes(sha256(
                N.to_bytes((N.bit_length() + 7) // 8, 'big') + G.to_bytes((G.bit_length() + 7) // 8,
                                                                          'big')).digest(), byteorder='big')
            public_B = (k * int(verify) + pow(G, b, N)) % N

            u = int.from_bytes(sha256(
                public_A.to_bytes((public_A.bit_length() + 7) // 8, 'big') + public_B.to_bytes(
                    (public_B.bit_length() + 7) // 8, 'big')).digest(), byteorder='big')

            conn.sendall(json.dumps({
                'status': 'success',
                'public_B': public_B,
                'salt': salt
            }).encode())

            Ss = pow((public_A * pow(int(verify), u, N)), b, N)
            M2 = int.from_bytes(sha256(
                public_A.to_bytes((public_A.bit_length() + 7) // 8, 'big') + public_B.to_bytes(
                    (public_B.bit_length() + 7) // 8, 'big') + Ss.to_bytes((Ss.bit_length() + 7) // 8,
                                                                           'big')).digest(),
                                byteorder='big')

            response = conn.recv(4096)
            data = json.loads(response.decode())

            if M2 == data.get('M1'):
                conn.sendall(json.dumps({
                    'status': 'success',
                    'message': f'\nПользователь {username} успешно аутентифицировался!'
                }).encode())
            else:
                conn.sendall(json.dumps({
                    'status': 'error',
                    'error_message': f'\nОшибка: Пользователь {username} не был аутентифицирован!'
                }).encode())

    except sqlite3.Error as e:
        conn.sendall(json.dumps({
            'status': 'error',
            'error_message': f'\nОшибка базы данных: {e}'
        }).encode())
        verify, salt = None, None


def create_post(client_data, cursor, conn, connect, sqlite3, json):

    username = client_data.get('login')
    text = client_data.get('text')

    try:
        cursor.execute('''SELECT 1 FROM users WHERE login = ?''', (username,))
        record = cursor.fetchone()

        if not record:
            conn.sendall(json.dumps({
                'status': 'error',
                'error_message': f'\nОшибка: Пользователь {username} не найден!'
            }).encode())

        cursor.execute('''INSERT INTO posts (login, post_text) VALUES (?, ?)''', (username, text))
        connect.commit()

        conn.sendall(json.dumps({
            'status': 'success',
            'message': '\nПост успешно добавлен!'
        }).encode())

    except sqlite3.Error as e:
        conn.sendall(json.dumps({
            'status': 'error',
            'error_message': f'\nОшибка базы данных: {e}'
        }).encode())


def view_my_posts(client_data, cursor, conn, json, sqlite3):

    username = client_data.get('login')

    try:
        cursor.execute(''' SELECT post_id, post_text FROM posts WHERE login = ? ''', (username, ))
        result = cursor.fetchall()

        # print(result)

        posts = [
            {'id': post_id, 'text': post_text, 'author': username}
            for post_id, post_text in result
        ]

        response_data = json.dumps({
            'status': 'success',
            'posts': posts
        }).encode()

        header = len(response_data).to_bytes(4, byteorder='big')
        conn.sendall(header)

        conn.sendall(response_data)

    except sqlite3.Error as e:
        error_data = json.dumps({
            'status': 'error',
            'error_message': f'\nОшибка базы данных: {e}'
        }).encode()
        header = len(error_data).to_bytes(4, byteorder='big')
        conn.sendall(error_data + header)


def view_user_posts(client_data, cursor, conn, json, sqlite3):
    username = client_data.get('login')

    try:
        cursor.execute(''' SELECT post_id, post_text FROM posts WHERE login = ? ''', (username,))
        result = cursor.fetchall()

        posts = [
            {'id': post_id, 'text': post_text, 'author': username}
            for post_id, post_text in result
        ]

        response_data = json.dumps({
            'status': 'success',
            'posts': posts
        }).encode()

        header = len(response_data).to_bytes(4, byteorder='big')
        conn.sendall(header)

        conn.sendall(response_data)

    except sqlite3.Error as e:
        error_data = json.dumps({
            'status': 'error',
            'error_message': f'\nОшибка базы данных: {e}'
        }).encode()
        header = len(error_data).to_bytes(4, byteorder='big')
        conn.sendall(error_data + header)


def delete_post(client_data, cursor, conn, sqlite3, json, connect):

    username = client_data.get('login')
    post_id = client_data.get('post_id')

    try:
        cursor.execute('''DELETE FROM posts WHERE login = ? AND post_id = ?''', (username, post_id))
        connect.commit()

        if cursor.rowcount == 0:
            conn.sendall(json.dumps({
                'status': 'error',
                'error_message': '\nОшибка: Не удалось удалить выбранный пост!'
            }).encode())
        else:
            conn.sendall(json.dumps({
                'status': 'success',
                'message': '\nПост успешно удален!'
            }).encode())

    except sqlite3.Error as e:
        conn.sendall(json.dumps({
            'status': 'error',
            'error_message': f'\nОшибка базы данных: {e}'
        }).encode())
        connect.rollback()