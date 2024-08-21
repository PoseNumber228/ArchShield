from create_database import CreateTables
from user_login import User


def main():
    """
    Антивирусная программа ArchShield.
    Антивирусная программа ArchShield выполянет основную задачу - искать вирусы.
    С этим программа отлично справляется благодаря своей постоянной актуальности
    и продвинутыми особенностями работы поиска вирусных файлов.
    """
    create_db = CreateTables()  # Создаём экземпляр класса CreateTables.
    create_db.create_user_table()  # Создаём таблицу users в базе данных.
    create_db.create_admin_table()   # Создаём таблицу admins в базе данных.
    create_db.create_virus_table()  # Создаём таблицу virus в базе данных.

    user = User()  # Создаём экземпляр класса User.
    user.login_registration()  # Вызываем основной метод работы с программой.


if __name__ == '__main__':
    print("'main.py запустилась самостоятельно.\n")
    main()  # Запускаем программу.
else:
    print("'main.py запустилась не самостоятельно.\n")
