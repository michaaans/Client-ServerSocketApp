from ClientHandlers.client_function import registration, authencation, create_post, view_my_posts, view_user_posts, delete_post
from connect import HOST, PORT
import socket


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        current_user = None  # Будет хранить данные авторизованного пользователя

        while True:
            if not current_user:
                # Главное меню (неавторизованный пользователь)
                print("\nГлавное меню:")
                print("1. Зарегистрироваться")
                print("2. Войти")
                print("3. Выход")

                choice = input("Выберите действие: ")

                if choice == '1':
                    registration(s)
                elif choice == '2':
                    current_user = authencation(s)  # Возвращает данные пользователя при успехе
                elif choice == '3':
                    break

            else:
                # Меню авторизованного пользователя
                print(f"\nДобро пожаловать {current_user.get('username')}!")
                print("1. Создать пост")
                print("2. Мои посты")
                print("3. Просмотреть посты другого пользователя")
                print("4. Удалить пост")
                print("5. Выйти из аккаунта")

                choice = input("Выберите действие: ")

                if choice == '1':
                    create_post(s, current_user.get('username'))

                elif choice == '2':
                    view_my_posts(s, current_user.get('username'), socket)

                elif choice == '3':
                    view_user_posts(s, socket)

                elif choice == '4':
                    delete_post(s, current_user.get('username'), socket)

                elif choice == '5':
                    current_user = None  # Выход из аккаунта


if __name__ == "__main__":
    main()

