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


class FundsType(Enum):
    """Типы используемых средств"""
    OWN = "own_funds"
    CREDIT = "credit_funds"
    MIXED = "mixed_funds"


# Тип описывающий структуру объекта, которая будет добавлена в историю операций
class Operation(TypedDict):
    type: OperationType
    amount: float
    datetime: datetime
    balance_after: float
    status: OperationStatus
    message: str
    funds_type: FundsType | None


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
                        message: str, funds_type: FundsType) -> None:
        """
            Внутренний метод для добавления операции в историю

            Args:
                operation_type (str): тип операции
                amount (float): сумма операции
                status (str): статус операции ('success' или 'fail')
                message (str): сообщение
                funds_type (str): тип используемых средств
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
            self._add_to_history(OperationType.INITIAL_DEPOSIT, balance, OperationStatus.SUCCESS,
                                 'Операция прошла успешно')

    def _add_to_history(self, operation_type, amount, status, message, funds_type=FundsType.OWN):

        operation: Operation = {
            'type': operation_type,
            'amount': amount,
            'datetime': datetime.now(),
            'balance_after': self._balance,
            'status': status,
            'message': message,
            'funds_type': funds_type,
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

    # ================================================= Кредитный счет =================================================


class CreditAccount(Account):
    """
    Кредитный счет, наследуемый от Account
    """

    def __init__(self, account_holder: str, balance: float, credit_limit: float):
        """
        Конструктор кредитного счета

        Args:
            account_holder (str): имя владельца счёта
            balance (float): начальный баланс счёта
            credit_limit (float): кредитный лимит (должен быть положительным)
        """
        if credit_limit < 0:
            raise ValueError('Кредитный лимит не может быть отрицательным')

        # Для кредитного счета разрешаем отрицательный баланс при инициализации
        # но проверяем, что он не ниже кредитного лимита
        if balance < -credit_limit:
            raise ValueError('Начальный баланс не может быть ниже кредитного лимита')

        self.credit_limit = credit_limit

        # Вызов конструктора супер класса при наследовании
        super().__init__(account_holder, balance)

    def _calculate_funds_type(self, amount: float) -> FundsType:
        """
        Определяет тип используемых средств для операции снятия

        Args:
            amount (float): сумма операции

        Returns:
            FundsType: тип использованных средств
        """
        if self._balance >= amount:
            return FundsType.OWN
        elif self._balance <= 0:
            return FundsType.CREDIT
        else:
            return FundsType.MIXED

    def withdraw(self, amount: float) -> bool:

        if amount <= 0:
            self._add_to_history(
                OperationType.WITHDRAW, amount, OperationStatus.FAIL,
                'Сумма не может быть отрицательной или нулевой'
            )
            return False

        # Проверяем, не превышает ли запрашиваемая сумма доступные средства
        if amount > self._balance + self.credit_limit:
            self._add_to_history(
                OperationType.WITHDRAW, amount, OperationStatus.FAIL,
                'Превышен кредитный лимит'
            )
            return False

        # тип используемых средств до изменения баланса
        funds_type = self._calculate_funds_type(amount)

        self._balance -= amount

        # добавляем в историю с информацией о типе средств
        self._add_to_history(
            OperationType.WITHDRAW, amount, OperationStatus.SUCCESS,
            'Операция прошла успешно', FundsType.CREDIT
        )
        return True

    def get_available_credit(self) -> float:
        """
        Возвращает сумму доступных кредитных средств

        Returns:
            float: доступные кредитные средства (текущий баланс + кредитный лимит)
        """
        return self._balance + self.credit_limit

    def get_credit_limit(self) -> float:
        """
        Возвращает кредитный лимит

        Returns:
            float: кредитный лимит
        """
        return self.credit_limit

    def get_used_credit(self) -> float:
        """
        Возвращает сумму использованных кредитных средств

        Returns:
            float: использованные кредитные средства (отрицательная часть баланса)
        """
        return max(-self._balance, 0)


if __name__ == '__main__':
    print('======= Account =======')
    account = Account("Иван Иванов", 1000)
    #
    # # Операции
    account.deposit(500)
    account.withdraw(200)
    account.withdraw(2000)  # Неудачная попытка (недостаточно средств)
    account.deposit(-100)  # Неудачная попытка (отрицательная сумма)

    print(account.get_history())

    print('======= CreditAccount =======')

    credit_account = CreditAccount("Петр Петров", 1000, 5000)

    print(f"Начальный баланс: {credit_account.get_balance()} руб.")
    print(f"Кредитный лимит: {credit_account.get_credit_limit()} руб.")
    print(f"Доступные средства: {credit_account.get_available_credit()} руб.")

    # Операции с использованием кредитных средств
    credit_account.withdraw(3000)  # 1000 собственных + 2000 кредитных

    print(credit_account.get_history())
