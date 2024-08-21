import psycopg2
import configparser
import csv
import os


class ConnectionDataBase:
    """
    Класс подключения к локальной БД антивируса ArchShield.
    """

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


class DataBaseOperation:
    """
    Класс DataBaseOperation реализует методы для работы admin-база данных.
    - show_virus_list - позволяет администратору вывести информацию о всех
      вирусах, когда-либо обнаруженных на ПК пользователя.
    - export_to_csv - позволяет администратору вывести информацию метода
      show_virus_list в CSV-файл.
    - delete_user - позволяет администратору удалить пользователя по его логину.
    - add_virus_info - позволяет администратору добавить информацию о вирусах в
      локальную БД антивируса ArchShield.
    """

    def __init__(self):
        self.connection = ConnectionDataBase().get_connection()
        # Подключаемся к локальной базе данных.

    def show_virus_list(self, login):
        """
        Метод show_virus_list - позволяет администратору вывести информацию о
        всех
        вирусах, когда-либо обнаруженных на ПК пользователя.
        """
        try:
            self.connection = ConnectionDataBase().get_connection()
            # Подключаемся к локальной базе данных

            with self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM virus WHERE virus_owner = %s;", (login,)
                )  # Выводит информацию о вирусе, у пользователя с введенным
                # администратором логином.
                viruses = cursor.fetchall()

                if viruses:
                    print(f"[INFO] Информация по вирусам пользователя {login}:")
                    for virus in viruses:
                        print(f"__{virus}__")
                        self.export_to_csv(viruses)
                else:
                    print(f"[INFO] Пользователь с логином {login} не найден.")

        except Exception as _ex:
            print("[INFO] Ошибка работы с PostgreSQL", _ex)  # Выводим статус
            # локальной базы данных.
        finally:
            self.connection.close()  # Закрываем соединение с базой данных.

    @staticmethod
    def export_to_csv(data):
        """
        Метод export_to_csv - позволяет администратору вывести информацию метода
        show_virus_list в CSV-файл.
        """
        try:
            csv_file_path = os.path.join(os.getcwd(), 'virus_data.csv')
            headers = [
                '__id__',
                '__file_path__',
                '__file_name__',
                '__hash_virus__',
                '__virus_owner__'
            ]  # Определяем заголовки в таблице CSV-файла.

            with open(
                    csv_file_path, mode='w', encoding='utf-8', newline=''
            ) as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(headers)
                writer.writerows(data)
            print(f"[INFO] Данные сохранены в файл {csv_file_path}")
            # Выводим  статус локальной базы данных.

        except Exception as e:
            print(f"[INFO] Ошибка записи в файл CSV: {e}")

    def delete_user(self, login):
        """
        Метод delete_user - позволяет администратору удалить пользователя
        по его логину.
        """
        try:
            self.connection = ConnectionDataBase().get_connection()
            # Подключаемся к локальной базе данных.

            with self.connection.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM users WHERE login = %s;", (login,)
                )  # Удаляет пользователя из БД по его логину.
                if cursor.rowcount > 0:
                    print(f"[INFO] Пользователь {login} был успешно удален.")
                else:
                    print(f"[INFO] Пользователь с логином {login} не найден.")

        except Exception as _ex:
            print("[INFO] Ошибка работы с PostgreSQL", _ex)  # Выводим статус
            # локальной базы данных.
        finally:
            self.connection.close()  # Закрываем соединение с базой данных.

    def add_virus_info(self):
        """
        Метод add_virus_info - позволяет администратору добавить информацию
        о вирусах в локальную БД антивируса ArchShield.
        """
        try:
            virus_name = input("Введите название вируса: ")
            virus_hash = input("Введите хеш вируса: ")

            self.connection = ConnectionDataBase().get_connection()
            # Подключаемся к локальной базе данных.

            with self.connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO virus("
                    "file_path,"
                    " virus_name,"
                    " hash_virus,"
                    " virus_owner"
                    ")"
                    " VALUES(%s, %s, %s, %s);",
                    (
                        "Added by administrator",
                        virus_name,
                        virus_hash,
                        "Added by administrator"
                    )
                )  # Добаляет информацию о вирусе в БД.

                if cursor.rowcount > 0:
                    print(
                        f"[INFO] Вирус с хешом - {virus_hash} был успешно "
                        f"добавлен."
                    )
                else:
                    print(f"[INFO] Вирус с хешом - {virus_hash} не добавлен.")

        except Exception as _ex:
            print("[INFO] Ошибка работы с PostgreSQL", _ex)  # Выводим статус
            # локальной базы данных.
        finally:
            self.connection.close()  # Закрываем соединение с базой данных.
