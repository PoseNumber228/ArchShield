from task_exceptions import Logger
from create_database import AddInfoDB
from tqdm import tqdm
from pathlib import Path
import hashlib
import requests
import os

logger = Logger().logger


class VirusFile:
    def __init__(self, owner_name):
        self.owner_name = owner_name
        self.add_info = AddInfoDB()
        self.api_available = True  # Изначально предполагаем, что API доступно

    def check_directory(self):
        while True:
            change_user_directory = input(
                "Введите путь к директории или выберите диск, "
                "на котором хотите запустить проверку: "
            )

            if not Path(change_user_directory).exists():
                print("Указанный путь не существует. Попробуйте еще раз.")
                continue

            files = list(Path(change_user_directory).rglob('*'))
            total_files = len(files)
            found_files = []

            with tqdm(total=total_files, desc="Проверка файлов", ncols=100) as pbar:
                for file_path in Path(change_user_directory).rglob('*'):
                    if file_path.is_file():
                        file_hash = self.calculate_file_hash(file_path)

                        # Проверка наличия вируса в API или локальной базе данных
                        if self.check_virus(file_hash):
                            found_files.append(file_path)
                            print(f"\nНайден файл с вирусной сигнатурой: {file_path}")
                            print(f"Имя файла: {file_path.name}")
                            self.add_info.register_virus(
                                str(file_path), file_path.name, file_hash, self.owner_name
                            )
                            self.delete_virus(file_path)

                        pbar.update(1)  # Обновление прогресс-бара

            if not found_files:
                print("\nНе найдено файлов с вирусными сигнатурами.")
            print("Проверка завершена.\n")

            while True:
                search_question = input("Желаете провести повторную проверку? (y/n): ").lower()
                if search_question == "y":
                    break  # Возвращает к вводу пути к директории
                elif search_question == "n":
                    print("Вы вышли из программы. До свидания!")
                    exit()
                else:
                    print("Некорректный ввод. Введите 'y' или 'n'.")

    def check_virus(self, hash_value):
        """Проверяет наличие вируса по хешу, сначала используя API, а затем локальную базу данных."""
        # Если API доступно, попробуем проверить через него
        if self.api_available:
            BASE_URL = "https://mb-api.abuse.ch/api/v1/fsaf/"
            headers = {'API-KEY': '1e022a8640318875e5d116a3261cfca5'}
            data = {'query': 'get_info', 'hash': hash_value}

            try:
                response = requests.post(BASE_URL, headers=headers, data=data)
                if response.status_code == 200:
                    data = response.json()
                    if 'query_status' in data and data['query_status'] == 'ok':
                        return True
                    else:
                        return False
                elif response.status_code == 404:
                    logger.error("Error 404: Resource not found.")
                    print("API недоступно (404: Resource not found). Будет использоваться только локальная база данных.")
                    self.api_available = False  # Отключаем дальнейшие запросы к API
                    return False
                else:
                    logger.error(f"Error when requesting API. Status code: {response.status_code}")
                    return False
            except requests.RequestException as e:
                logger.error(f"Request exception: {e}")
                print(f"Ошибка подключения к API: {e}. Будет использоваться только локальная база данных.")
                self.api_available = False  # Отключаем дальнейшие запросы к API
                return False

        # Если API недоступно или не обнаружено через API, проверяем локальную базу данных
        if self.add_info.check_virus_db(hash_value):
            return True

        return False

    @staticmethod
    def calculate_file_hash(file_path, hash_algorithm='SHA256'):
        """Вычисляет хеш файла."""
        hash_file = hashlib.new(hash_algorithm)

        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                hash_file.update(chunk)

        return hash_file.hexdigest()

    @staticmethod
    def delete_virus(file_path):
        """Удаляет файл с подтвержденной вирусной сигнатурой."""
        while True:
            try:
                delete_question = input("Удалить файл? (y/n): ").lower()
                if delete_question == "y":
                    os.remove(file_path)
                    print(f"Файл {file_path.name} успешно удален.")
                    break
                elif delete_question == "n":
                    break
                else:
                    print("Некорректный ввод. Введите 'y' или 'n'.")
            except OSError as e:
                print(f"Ошибка при удалении файла {file_path.name}: {e}")
                logger.error(f"Error deleting file {file_path.name}: {e}")
