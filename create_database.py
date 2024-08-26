import psycopg2
import bcrypt
import configparser


class ConnectionDataBase:
    """
    Класс подключения к локальной БД антивируса ArchShield.
    """
    def __init__(self):
        self.connection = self.get_connection()

    @staticmethod
    def get_connection():
        """
        Устанавливает соединение с базой данных PostgreSQL
        c помощью файла конфигурации БД db_config.ini.
        """

        config = configparser.ConfigParser()
        config.read('db_config.ini')

        host = config.get('database', 'host')
        user = config.get('database', 'user')
        password = config.get('database', 'password')
        db_name = config.get('database', 'db_name')

        connection = psycopg2.connect(
            host=host,
            user=user,
            password=password,
            database=db_name
        )
        connection.autocommit = True
        return connection


class CreateTables:
    """
    Класс CreateTables реализует создание таблиц users, admins и virus
    в локальной базе данных ArchShield.
    """

    def __init__(self):
        self.connection = ConnectionDataBase().get_connection()  #
        # Подключаемся к локальной базе данных.

    def create_user_table(self):
        """
        Метод create_user_table создаёт таблицу users, в которой хранится
        информация об пользователях.
        Таблица users содержит поля: id, login, password.
        """
        try:
            self.connection = ConnectionDataBase().get_connection()
            with self.connection.cursor() as cursor:
                cursor.execute(
                    """CREATE TABLE IF NOT EXISTS users(
                    id SERIAL PRIMARY KEY,
                    login VARCHAR(50) NOT NULL,
                    password VARCHAR(64) NOT NULL
                    );"""
                )  # Создаём таблицу users.
                print("[INFO] Таблица 'users' создана или уже существует.")

        except Exception as _ex:
            print("[INFO] Ошибка работы с PostgreSQL", _ex)  # Выводим статус
            # локальной базы данных.
        finally:
            if self.connection:
                self.connection.close()  # Закрываем соединение с базой данных.
                print('[INFO] Соединение с PostgreSQL завершено.')

    def create_admin_table(self):
        """
        Метод create_admin_table создаёт таблицу admins, в которой хранится
        информация об админе.
        Таблица admins содержит поля: id, login, password.
        """
        try:
            self.connection = ConnectionDataBase().get_connection()
            # Подключаемся к локальной базе данных.
            with self.connection.cursor() as cursor:
                cursor.execute(
                    """CREATE TABLE IF NOT EXISTS admins(
                    id serial PRIMARY KEY,
                    login varchar(50) NOT NULL,
                    password varchar(64) NOT NULL
                    );"""
                )  # Созданём таблицу admins.
                print("[INFO] Таблица 'admins' создана или уже существует.")

        except Exception as _ex:
            print("[INFO] Ошибка работы с PostgreSQL", _ex)  # Выводим статус
            # локальной базы данных.
        finally:
            if self.connection:
                self.connection.close()  # Закрываем соединение с базой данных.
                print('[INFO] Соединение с PostgreSQL завершено.')

    def create_virus_table(self):
        """
        Метод create_virus_table создаёт таблицу virus,
        в которой будет хранится информация о вирусах, обнаруженной
        ативирусом или добавленной администратором антивируса.
        Таблица virus содержит поля: id, file_path, virus_name, hash_virus,
        virus_owner.
        """
        try:
            self.connection = ConnectionDataBase().get_connection()
            # Подключаемся к локальной базе данных.
            with self.connection.cursor() as cursor:
                cursor.execute(
                    """CREATE TABLE IF NOT EXISTS virus(
                    id serial PRIMARY KEY,
                    file_path varchar(1000) NOT NULL,
                    virus_name varchar(100) NOT NULL,
                    hash_virus varchar(65) NOT NULL,
                    virus_owner varchar(50) NOT NUll
                    );"""
                )  # Создаём таблицу virus.
                print("[INFO] Таблица 'virus' создана или уже существует.")

        except Exception as _ex:
            print("[INFO] Ошибка работы с PostgreSQL", _ex)  # Выводим статус
            # локальной базы данных.
        finally:
            if self.connection:
                self.connection.close()  # Закрываем соединение с базой данных.
                print('[INFO] Соединение с PostgreSQL завершено.')


class AddInfoDB:
    """
    Класс AddInfoDB реализует следующие методы обработки информации в БД:
    - check_user - проверяет, есть ли зарегистрированный пользвателя в
      программе антивирус ArchShield.
    - register_user - регистрирует пользователя в программе антивирус
      ArchShield и кодирует его пороли в БД хешом.
    - verify_user - проверяет, есть ли зарегистрированный пользвателя в
      программе антивирус ArchShield, если есть, то сверяет его пароль с
      паролем в БД, который он вводил при регистрации.
    - check_admin - проверяет, есть ли администратор в
      программе антивирус ArchShield.
    - verify_admin - проверяет, есть ли зарегистрированный администратор в
      программе антивирус ArchShield, если есть, то сверяет его пароль с
      паролем в БД.
    - register_virus - даёт возможность администратору антивируса ArchShield
      добавить в БД информацию о вирусе.
    - check_virus_db - даёт возможность администратору антивируса ArchShield
      вывести информацию о вирусах, обнаруженных на ПК пользователей по их
      логину.
    """

    def __init__(self):
        self.connection = ConnectionDataBase().get_connection()
        # Подключаемся к локальной базе данных.

    def check_user(self, login):
        """
        Метод check_user - проверяет, есть ли зарегистрированный пользвателя в
        программе антивирус ArchShield.
        """
        try:
            self.connection = ConnectionDataBase().get_connection()
            # Подключаемся к локальной базе данных.
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT EXISTS(SELECT 1 FROM users WHERE login=%s);",
                    (login,)
                )  # Проверяем, если ли логин в БД в таблице users (True/False).
                return cursor.fetchone()[0]  # Возращает первое значение из
                # первой колонки строки.

        except Exception as _ex:
            print("[INFO] Ошибка работы с PostgreSQL", _ex)
        finally:
            self.connection.close()  # Закрываем соединение с базой данных.

    def register_user(self, login, user_password):
        """
        Метод register_user - регистрирует пользователя в программе антивирус
        ArchShield и кодирует его пороли в БД хешом.
        """
        try:
            self.connection = ConnectionDataBase.get_connection()
            # Подключаемся к локальной базе данных.
            with self.connection.cursor() as cursor:
                hashed_password = bcrypt.hashpw(
                    user_password.encode(), bcrypt.gensalt()
                ).decode('utf-8')  # Преобразует строку с паролем
                # пользователя в байты, а затем преобразует его в хеш,
                # добавляя "соль", а затем преобразует байты обратно в
                # строку, чтобы хеш можно было хранить в БД в виде строки.
                cursor.execute(
                    "INSERT INTO users (login, password) VALUES (%s, %s);",
                    (login, hashed_password)
                )
                print(f"[INFO] Пользователь {login} успешно зарегистрирован.")

        except Exception as _ex:
            print("[INFO] Ошибка работы с PostgreSQL", _ex)  # Выводим статус
            # локальной базы данных.
        finally:
            self.connection.close()  # Закрываем соединение с базой данных.

    def verify_user(self, login, user_password):
        """
        Метод verify_user - проверяет, есть ли зарегистрированный пользвателя в
        программе антивирус ArchShield, если есть, то сверяет его пароль с
        паролем в БД, который он вводил при регистрации.
        """
        try:
            self.connection = ConnectionDataBase.get_connection()
            # Подключаемся к локальной базе данных.
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT password FROM users WHERE login=%s;", (login,)
                )  # Выводим пароль пользователя и сравниваем пароль с логином.
                used_password = cursor.fetchone()
                if used_password is None:
                    return False
                return bcrypt.checkpw(
                    user_password.encode(), used_password[0].encode()
                )  # Преобразовываем введенный пользователем пароль в байты.
                # Раскодируем введенны в БД строку обратно в байты, отнимая от
                # нее соль преобразуя в байты и сравниваем результы.

        except Exception as _ex:
            print("[INFO] Ошибка работы с PostgreSQL", _ex)  # Выводим статус
            # локальной базы данных.
            return False
        finally:
            self.connection.close()  # Закрываем соединение с базой данных.

    def check_admin(self, login):
        """
        Метод check_admin - проверяет, есть ли администратор в
        программе антивирус ArchShield.
        """
        try:
            self.connection = ConnectionDataBase().get_connection()
            # Подключаемся к локальной базе данных.
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT EXISTS(SELECT 1 FROM admins WHERE login=%s);",
                    (login,)
                )
                return cursor.fetchone()[0]  # Проверяет есть ли администратор
                # в системе БД с таким логином.

        except Exception as _ex:
            print("[INFO] Ошибка работы с PostgreSQL", _ex)  # Выводим статус
            # локальной базы данных.
        finally:
            self.connection.close()  # Закрываем соединение с базой данных.

    def verify_admin(self, login, admin_password):
        """
        Метод verify_admin - проверяет, есть ли зарегистрированный
        администратор в программе антивирус ArchShield, если есть,
        то сверяет его пароль с паролем в БД.
        """
        try:
            self.connection = ConnectionDataBase.get_connection()
            # Подключаемся к локальной базе данных.
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT password FROM admins WHERE login=%s;", (login,)
                )
                used_password = cursor.fetchone()
                if used_password is None:
                    return False
                return bcrypt.checkpw(
                    admin_password.encode(), used_password[0].encode()
                )  # Раскодируем введенны в БД строку обратно в байты, отнимая от
                # нее соль преобразуя в байты и сравниваем результы.

        except Exception as _ex:
            print("[INFO] Ошибка работы с PostgreSQL", _ex)  # Выводим статус
            # локальной базы данных.
            return False
        finally:
            self.connection.close()  # Закрываем соединение с базой данных.

    def register_virus(self, file_path, virus_name, hash_virus, virus_owner):
        """
        Метод register_virus - даёт возможность администратору антивируса
        ArchShield добавить в БД информацию о вирусе.
        """
        try:
            self.connection = ConnectionDataBase.get_connection()
            # Подключаемся к локальной базе данных.
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO virus("
                    "file_path, virus_name, hash_virus, virus_owner)"
                    " VALUES (%s, %s, %s, %s);",
                    (file_path, virus_name, hash_virus, virus_owner)
                )  # Добавляет данные вируса в локальную БД антивируса.
            print(f"[INFO] Вирус {virus_name} добавлен в базу данных.")

        except Exception as _ex:
            print("[INFO] Ошибка работы с PostgreSQL", _ex)  # Выводим статус
            # локальной базы данных.
        finally:
            self.connection.close()  # Закрываем соединение с базой данных.

    def check_virus_db(self, hash_virus):
        """
        Метод check_virus_db - даёт возможность администратору антивируса
        ArchShield вывести информацию о вирусах, обнаруженных на ПК
        пользователей по их логину.
        """
        try:
            self.connection = ConnectionDataBase.get_connection()
            # Подключаемся к локальной базе данных.
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT hash_virus FROM virus WHERE hash_virus = %s;",
                    (hash_virus,)
                )  # Выводит данные о вирусе по логину пользователя, на чьём
                # ПК он был найдет.
                result = cursor.fetchone()
                if result:
                    return True
                else:
                    return False
        except Exception as _ex:
            print("[INFO] Ошибка работы с PostgreSQL", _ex)  # Выводим статус
            # локальной базы данных.
            return False

        finally:
            self.connection.close()  # Закрываем соединение с базой данных.
