from task_exceptions import BadNameError, BadPasswordError


class ValueException:
    """Создаём класс Value."""

    @staticmethod
    def exc_name(login):
        """Функция проверки и вывода сообщений ошибки для имени."""
        if len(login) < 4:
            raise BadNameError(login)

    @staticmethod
    def exc_password(user_password):
        """Функция проверки и вывода сообщений ошибки для пароля
        пользователя."""
        if not (8 <= len(str(user_password)) <= 20):
            raise BadPasswordError(user_password)
