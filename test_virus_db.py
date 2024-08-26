import unittest
from pathlib import Path
from check_files import VirusFile


class TestVirusFile(unittest.TestCase):
    """
    Класс Проверки вычисления хеша.
    """

    def test_calculate_file_hash(self):
        test_file_path = Path("test_file.txt")  # Указываем путь к  тестовому
        # файлу.

        virus_file = VirusFile("test_file")  # Создаем экземпляр класса
        # VirusFile.

        expected_hash = \
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        # Ожидаемый хеш для данных.

        calculated_hash = virus_file.calculate_file_hash(
            test_file_path, hash_algorithm='SHA256'
        )  # Вычисляем хеш тестового файла.

        self.assertEqual(calculated_hash, expected_hash)  # Проверяем,
        # соответствует ли вычисленный хеш ожидаемому значению.


if __name__ == '__main__':
    unittest.main()
