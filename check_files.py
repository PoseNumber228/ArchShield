from task_exceptions import Logger
from create_database import AddInfoDB
from tqdm import tqdm
from pathlib import Path
import hashlib
import requests
import os

logger = Logger().logger


class VirusFile:
    """
    Класс VirusFile реализует следующие задачи:
    - Проходит по каждому файлу и подфайлу и преобразует его в хеш SHA256.
      Данное преобразование проходит не целым файлом, а по 4КБ, что положительно
      сказывается на скорости выполнения программой своей основной задачи.
    - Класс получает информацию по API из открытой базы данных MalwareBazaar,
      при условии, что сервер доступен. В противном случае сигнатуры вирусов
      будут извлекаться из локальной базы данных, которые добавляются при
      каждом обнаружении вирусов на машине или с помощью администратора
      программы.
     """

    def __init__(self, owner_name):
        self.owner_name = owner_name
        self.add_info = AddInfoDB()
        self.api_available = True

    def check_directory(self):
        """
        Метод check_directory проходит по каждому файлу в выбранной
        директории и сравнивает его с файлами из базы данных MalwareBazaar.
        """
        while True:
            change_user_directory = input(
                "Введите путь к директории или выберите диск, "
                "на котором хотите запустить проверку: "
            )

            if not Path(change_user_directory).exists():
                print("Указанный путь не существует. Попробуйте еще раз.")
                continue

            files = list(Path(change_user_directory).rglob('*'))  # Возращает
            # список файлов. rglob рекурсивно ищет файлы в указанной
            # директории всех папок и файлов.
            total_files = len(files)
            found_files = []

            with tqdm(
                    total=total_files, desc="Проверка файлов", ncols=100
            ) as pbar:  # Создаём переменную pbar, которая
                # будет возращать process bar, каждый шаг-один элемент.

                for file_path in Path(change_user_directory).rglob('*'):
                    if file_path.is_file():
                        file_hash = self.calculate_file_hash(file_path)
                        # вызывается метод calculate_file_hash, который
                        # преобразует каждый файл директории в hash.

                        if self.get_hash(file_hash):  # Проверка наличия
                            # вируса в API, если сервер доступен
                            found_files.append(file_path)
                            print(
                                f"\nНайден файл с вирусной сигнатурой: "
                                f"{file_path}"
                            )
                            print(f"Имя файла: {file_path.name}")
                            self.add_info.register_virus(
                                str(file_path),
                                file_path.name,
                                file_hash,
                                self.owner_name
                            )  # Добавляет информацию о вирусе в локальную БД.
                            self.delete_virus(file_path)
                            continue

                        # Локальная проверка в базе данных
                        elif self.add_info.check_virus_db(file_hash):
                            found_files.append(file_path)
                            print(
                                f"\nНайден файл с вирусной сигнатурой (по "
                                f"локальной БД): {file_path}"
                            )
                            print(f"Имя файла: {file_path.name}")
                            self.add_info.register_virus(
                                str(file_path),
                                file_path.name,
                                file_hash,
                                self.owner_name
                            )  # Добавляет информацию о вирусе в локальную БД.
                            self.delete_virus(file_path)

                        pbar.update(1)  # Обновление прогресс-бара

            if not found_files:
                print("\nНе найдено файлов с вирусными сигнатурами.")
            print("Проверка завершена.\n")

            while True:
                search_question = input(
                    "Желаете провести повторную проверку? (y/n): "
                ).lower()
                if search_question == "y":
                    break  # Возвращает к вводу пути к директории
                elif search_question == "n":
                    print("Вы вышли из программы. До свидания!")
                    exit()
                else:
                    print("Некорректный ввод. Введите 'y' или 'n'.")

    def get_hash(self, hash_value):
        """
        Метод get_hash получает с сервера MalwareBazaar через API хеши
        вирусных файлов. В случае недоступности сервера - выдаёт сообщение
        об ошибке и передаёт задачу сверяхть хеш-файлы в локальной БД.
        """
        if self.api_available:
            base_url = "https://mb-api.abuse.ch/api/v1/"  # URL БД с
            # вирусными сигнатурами MalwareBazaar.
            headers = {
                'API-KEY': '1e022a8640318875e5d116a3261cfca5'
            }  # Личный API-LEY для подключения к БД с
            # вирусными сигнатурами MalwareBazaar.
            data = {
                'query': 'get_info',
                'hash': hash_value
            }  # Присваиваем переменной data словарь, в котором будет
            # хранится информация о вирусных сигнатурах и хеше в SHA-256
            # формате.

            try:
                response = requests.post(
                    base_url,
                    headers=headers,
                    data=data
                )  # Отправляет HTTP POST-запрос на сервер
                if response.status_code == 200:
                    if 'query_status' in data and data['query_status'] == 'ok':
                        return True
                    else:
                        return False
                elif response.status_code == 404:
                    logger.error("Error 404: Resource not found.")
                    print(
                        "\nAPI недоступно (404: Resource not found)."
                        "Будет использоваться только локальная база данных."
                    )
                    self.api_available = False  # Отключаем дальнейшие
                    # запросы  к API
                else:
                    logger.error(
                        f"Error when requesting MalwareBazaar. Status code: "
                        f"{response.status_code}"
                    )
                    return False
            except requests.RequestException as e:
                logger.error(f"Request exception: {e}")
                print(
                    f"Ошибка подключения к API: {e}. Будет использоваться "
                    f"только локальная база данных."
                )
                self.api_available = False  # Отключаем дальнейшие запросы к API
                return False

                # Если API недоступно или не обнаружено через API, проверяем
                # локальную базу данных
            if self.add_info.check_virus_db(hash_value):
                return True

            return False

    @staticmethod
    def calculate_file_hash(file_path, hash_algorithm='SHA256'):
        """
        Метод calculate_file_hash преобразует каждый файл в хеш
        алгоритмом SHA-256 по 4КВ, чтобы экономить ОЗУ компьютера.
        """
        hash_file = hashlib.new(hash_algorithm)

        with open(file_path, 'rb') as f:  # Открываем файл для чтения.
            # rb- чтение в бинарном режиме
            while chunk := f.read(4096):  # Присваивание внутри цикла.
                # Данный цикл проверяет, не является ли строка пустой.
                hash_file.update(chunk)

        return hash_file.hexdigest()  # Возращает хеш файла в
        # шестнадцатеричном формате.

    @staticmethod
    def delete_virus(file_path):
        """
        Метод delete_virus запрашивает у пользоватебя, нужно ли удалять
        найденный ею вирусный файл.
        """
        while True:
            try:
                delete_question = input("Удалить файл? (y/n): ").lower()
                if delete_question == "y":
                    os.remove(file_path)  # Метод удаления файла из системы.
                    print(f"Файл {file_path.name} успешно удален.")
                    break
                elif delete_question == "n":
                    break
                else:
                    print(
                        "Некорректный ввод. Введите 'y' или 'n'."
                    )
            except OSError as e:
                print(f"Ошибка при удалении файла {file_path.name}: {e}")
                logger.error(f"Error deleting file {file_path.name}: {e}")
