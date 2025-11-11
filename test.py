from abc import ABC, abstractmethod
from typing import List, TypedDict, Literal
from enum import Enum, auto
from datetime import datetime


# ================================================= Типы =================================================

class OperationType(Enum):
    """Типы операций по счету с читаемыми значениями"""
    DEPOSIT = "deposit"
    WITHDRAW = "withdraw"
    INITIAL_DEPOSIT = "initial_deposit"
    BALANCE = "request_balance"


class OperationStatus(Enum):
    """Статусы операций с читаемыми значениями"""
    SUCCESS = "success"
    FAIL = "fail"


# Тип описывающий структуру объекта, которая будет добавлена в историю операций
class Operation(TypedDict):
    type: OperationType
    amount: float
    datetime: datetime
    balance_after: float
    status: OperationStatus
    message: str


class IAccount(ABC):
    """Интерфейс для банковского счета"""

    @abstractmethod
    def __init__(self, account_holder: str, balance: float) -> None:
        """
            Конструктор класса Account

            Args:
                account_holder (str): имя владельца счёта
                balance (float, optional): начальный баланс счёта. По умолчанию 0.
        """
        pass

    @abstractmethod
    def deposit(self, amount: float) -> bool:
        """
             Метод для пополнения счёта

             Args:
                 amount (float): сумма пополнения

             Returns:
                 bool: True если операция успешна, False если нет
         """
        pass

    @abstractmethod
    def withdraw(self, amount: float) -> bool:
        """
           Метод для снятия средств

           Args:
               amount (float): сумма снятия

           Returns:
               bool: True если операция успешна, False если нет
        """
        pass

    @abstractmethod
    def get_balance(self) -> float:
        """
            Возвращает текущий баланс

            Returns:
                float: текущий баланс
        """
        pass

    @abstractmethod
    def get_history(self) -> List[Operation]:
        """
             Возвращает историю операций

             Returns:
                 list: список операций в формате словарей
        """
        pass

    @abstractmethod
    def _add_to_history(self, operation_type: OperationType, amount: float, status: OperationStatus,
                        message: str) -> None:
        """
            Внутренний метод для добавления операции в историю

            Args:
                operation_type (str): тип операции
                amount (float): сумма операции
                status (str): статус операции ('success' или 'fail')
        """
        pass

    @abstractmethod
    def get_holder(self) -> str:
        """
            Возвращает данные владельца счета

             Returns:
                 str
        """
        pass


# ================================================= Реализация класса =================================================

class Account(IAccount):
    def __init__(self, account_holder, balance):

        # Проверка на отрицательный баланс
        if (balance < 0):
            raise ValueError('Баланс не может быть отрицательным')

        self.holder = account_holder
        self._balance = balance
        self.operations_history = []

        # Добавляем начальный баланс в историю, если он больше 0
        if balance > 0:
            self._add_to_history(OperationType.INITIAL_DEPOSIT, balance, OperationStatus.SUCCESS, 'Операция прошла успешно')

    def _add_to_history(self, operation_type, amount, status, message):

        operation: Operation = {
            'type': operation_type,
            'amount': amount,
            'datetime': datetime.now(),
            'balance_after': self._balance,
            'status': status,
            'message': message
        }

        self.operations_history.append(operation)

    def deposit(self, amount):
        if (amount < 0):
            self._add_to_history(OperationType.DEPOSIT, amount, OperationStatus.FAIL,
                                 'Сумма не может быть отрицательной')
            # Возвращаем статус операции
            return False

        self._balance += amount
        self._add_to_history(OperationType.DEPOSIT, amount, OperationStatus.SUCCESS, 'Операция прошла успешно')

        # Возвращаем статус операции
        return True

    def withdraw(self, amount):
        # флаг указывающий на не валидность снимаемой суммы
        is_invalid_amount: bool = amount <= 0
        # флаг указывающий на то, что баланс меньше снимаемой суммы
        is_small_balance: bool = amount > self._balance

        # определяем сообщение б ошибке
        if is_invalid_amount:
            error_message = 'Сумма не может быть отрицательной или нулевой'
        elif is_small_balance:
            error_message = 'Недостаточно средств на балансе'
        else:
            error_message = ''  # или вообще не определять

        if is_invalid_amount or is_small_balance:
            self._add_to_history(OperationType.WITHDRAW, amount, OperationStatus.FAIL, error_message)
            # Возвращаем статус операции
            return False

        self._balance -= amount
        self._add_to_history(OperationType.WITHDRAW, amount, OperationStatus.SUCCESS, 'Операция прошла успешно')

        # Возвращаем статус операции
        return True

    def get_balance(self):
        return self._balance

    def get_holder(self):
        return self.holder

    def get_history(self):
        return self.operations_history


if __name__ == '__main__':
    account = Account("Иван Иванов", 1000)

    # Операции
    account.deposit(500)
    account.withdraw(200)
    account.withdraw(2000)  # Неудачная попытка (недостаточно средств)
    account.deposit(-100)  # Неудачная попытка (отрицательная сумма)

    print(account.get_history())
