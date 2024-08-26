from task_exceptions import Logger
from create_database import AddInfoDB
from database_operation import DataBaseOperation
from check_files import VirusFile
from value_exceptions import ValueException
from task_exceptions import BadPasswordError, BadNameError

value_error = ValueException
logger = Logger().logger


class User:
    def __init__(self):
        self.login = None

    def login_registration(self):
        add_info = AddInfoDB()
        db_operation = DataBaseOperation()

        while True:
            try:
                print('Приветствуем Вас в антивирусной программе "ArchShield"')

                login = input(
                    "Введите Ваш login.\n"
                    "(exit - для выхода): "
                )
                value_error.exc_name(login)

                if add_info.check_admin(login):
                    while True:
                        registration_check_password = input(
                            "Введите Ваш пароль. "
                        )
<<<<<<< HEAD
                        if add_info.verify_admin(login, registration_check_password):
=======
                        if add_info.verify_admin(login,
                                                 registration_check_password):
>>>>>>> c694d89d5e5d950af0fb438af2e2db221d0b4ffa
                            print(
                                f"Ваш пароль подтвежден. \n"
                                f"Добро пожаловать, {login}"
                            )

                            while True:
                                print(
                                    "1. Вывести список вирусов "
                                    "пользователя по его логину. "
                                )
                                print(
                                    "2. Добавить новый вирус в базу данных. "
                                )
                                print(
                                    "3. Удалить пользователя. "
                                )
                                print(
                                    "4. Выйти из программы. "
                                )

                                admin_choice = input(
                                    "Выберите действие (1/2/3/4): "
                                )
                                if admin_choice == "1":
                                    user_virus_list = input(
                                        "Введите логин пользователя, "
                                        "по которому хотите узнать "
                                        "количество устранённых вирусов. \n"
                                        "Введите 'exit' для выхода: "
                                    )
                                    if user_virus_list == 'exit':
                                        print(
<<<<<<< HEAD
                                            "Вы вышли из программы. До свидания!"
                                        )
                                        exit()
                                    else:
                                        db_operation.show_virus_list(user_virus_list)
                                elif admin_choice == "2":
                                    to_exit = input(
                                        "Добавление нового вируса в базу данных. "
=======
                                            "Вы вышли из программы. До "
                                            "свидания!"
                                        )
                                        exit()
                                    else:
                                        db_operation.show_virus_list(
                                            user_virus_list)
                                elif admin_choice == "2":
                                    to_exit = input(
                                        "Добавление нового вируса в базу "
                                        "данных. "
>>>>>>> c694d89d5e5d950af0fb438af2e2db221d0b4ffa
                                        "Нажмите Enter.\n"
                                        "Введите 'exit' для выхода: "
                                    )
                                    if to_exit == 'exit':
                                        print(
<<<<<<< HEAD
                                            "Вы вышли из программы. До свидания!"
=======
                                            "Вы вышли из программы. До "
                                            "свидания!"
>>>>>>> c694d89d5e5d950af0fb438af2e2db221d0b4ffa
                                        )
                                        exit()
                                    else:
                                        db_operation.add_virus_info()
                                elif admin_choice == "3":
                                    user_to_delete = input(
<<<<<<< HEAD
                                        "Введите логин пользователя для удаления: \n"
=======
                                        "Введите логин пользователя для "
                                        "удаления: \n"
>>>>>>> c694d89d5e5d950af0fb438af2e2db221d0b4ffa
                                        "Введите 'exit' для выхода: "
                                    )
                                    if user_to_delete == 'exit':
                                        print(
<<<<<<< HEAD
                                            "Вы вышли из программы. До свидания!"
=======
                                            "Вы вышли из программы. До "
                                            "свидания!"
>>>>>>> c694d89d5e5d950af0fb438af2e2db221d0b4ffa
                                        )
                                        exit()
                                    else:
                                        db_operation.delete_user(user_to_delete)
                                elif admin_choice == "4":
                                    print("Вы вышли из программы. До свидания!")
                                    exit()
                                else:
                                    print(
                                        "Некорректный ввод. Попробуйте снова."
                                    )

                        elif registration_check_password == 'exit':
                            print("Вы вышли из программы. До свидания!")
                            exit()

                        else:
                            print(
                                "Пароль неверный, повторите пароль еще раз!\n"
<<<<<<< HEAD
                                "Или выйдите из программы с помощью команды 'exit'. "
=======
                                "Или выйдите из программы с помощью команды "
                                "'exit'. "
>>>>>>> c694d89d5e5d950af0fb438af2e2db221d0b4ffa
                            )

                elif login.lower() == 'exit':
                    print("Вы вышли из программы. До свидания!")
                    exit()

                elif not add_info.check_user(login):
                    registration_question = input(
                        "Желаете зарегистрироваться?\n"
                        "Введите 'y' или 'n': "
                    ).lower()
                    while True:
                        if registration_question == "y":
                            registration_password = input(
                                "Придумайте пароль для Вашей учётной записи. "
                            )
                            value_error.exc_password(registration_password)
                            while True:
                                registration_check_password = input(
                                    "Повторите пароль. "
                                )
<<<<<<< HEAD
                                if registration_password == registration_check_password:
                                    add_info.register_user(login, registration_password)
=======
                                if registration_password == \
                                        registration_check_password:
                                    add_info.register_user(login,
                                                           registration_password)
>>>>>>> c694d89d5e5d950af0fb438af2e2db221d0b4ffa
                                    print(
                                        f"Ваш пароль подтвежден. \n"
                                        f"Добро пожаловать, {login}"
                                    )
                                    self.login = login
                                    self.check_virus()
                                    return login
                                else:
                                    print(
<<<<<<< HEAD
                                        "Ваш пароль не соответствует введенному ранее. "
=======
                                        "Ваш пароль не соответствует "
                                        "введенному ранее. "
>>>>>>> c694d89d5e5d950af0fb438af2e2db221d0b4ffa
                                        "Повторите попытку. "
                                    )
                        elif registration_question == "n":
                            print("Вы вышли из программы. До свидания!")
                            exit()
                        else:
                            print("Вы ввели неверное значение.")

                else:
                    while True:
                        registration_check_password = input(
                            "Введите Ваш пароль. "
                        )
<<<<<<< HEAD
                        if add_info.verify_user(login, registration_check_password):
=======
                        if add_info.verify_user(login,
                                                registration_check_password):
>>>>>>> c694d89d5e5d950af0fb438af2e2db221d0b4ffa
                            print(
                                f"Ваш пароль подтвежден. \n"
                                f"Добро пожаловать, {login}"
                            )
                            self.login = login
                            self.check_virus()
                            return login
                        elif registration_check_password == 'exit':
                            print("Вы вышли из программы. До свидания!")
                            exit()
                        else:
                            print(
                                "Пароль неверный, повторите пароль еще раз!\n"
                                "Или выйдите из программы командой 'exit'. "
                            )
            except (BadPasswordError, BadNameError) as task_error:
                print(f"Ошибка {task_error}")
            except ValueError:
                print("Некорректный ввод, пожалуйста, попробуйте снова.")

    def check_virus(self):
        search_virus = VirusFile(self.login)
        while True:
            search_question = input(
                f"{self.login}, желаете проверить систему на вирусы?\n"
                "Введите 'y' или 'n': "
            ).lower()
            if search_question == "y":
                search_virus.check_directory()
            elif search_question == "n":
                print(f"Вы вышли из программы. До свидания, {self.login}!")
                exit()
            else:
                print(
                    f"{self.login}, Вы ввели неверное значение. "
                    "Попробуйте еще раз."
                )
