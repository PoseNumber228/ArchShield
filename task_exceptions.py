import logging


class Logger:
    def __init__(self):
        logging.basicConfig(filename="bd_logger.log", filemode="w")
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)


logger = Logger().logger


class BadPasswordError(Exception):
    """
    Создание исключения для неверно заданного пароля аккаунта.
    """

    def __init__(
            self, user_password,
            message="Количество символов в пароле должно быть не "
                    "менее восьми символов и не превышать двадцати. "
    ):
        self.user_password = user_password
        self.message = message
        super().__init__(message)
        logger.error(
            f"BadPasswordError: {message} - Given password: {user_password}")


class BadNameError(Exception):
    """
    Создание исключения для неверно заданного имени.
    """

    def __init__(
            self, login, message="Длина имени не должна менее четырёх "
                                 "символов. "
    ):
        self.login = login
        self.message = message
        super().__init__(message)
        logger.error(
            f"BadPasswordError: {message} - Given login: {login}")
