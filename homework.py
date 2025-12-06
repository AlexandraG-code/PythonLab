"""
    Задание 1

"""


def get_medium_char(string: str):
    # Обработка пустой строки
    if not string or len(string) == 0:
        return ""

    # Флаг, который говорит о том, что количество символов в строке четное или нечетное
    is_even = len(string) % 2 == 0
    index = len(string) // 2

    if is_even:
        # Возвращаем два средних символа
        return string[index - 1: index + 1]
    else:
        # Возвращаем один средний символ
        return string[index]


"""
    Задание 2 Поиск пар

"""
def create_pairs(boys: list[str], girls: list[str]):
    # нет ищем пары, если списки разной длины
    if len(boys) != len(girls):
        return 'Внимание, кто-то может остаться без пары!'

    # отсортированные списки
    sorted_boys = sorted(boys)
    sorted_girls = sorted(girls)
    # итоговый результат со списком пар
    print_result = "Результат:\nИдеальные пары:\n"

    for index, boy in enumerate(sorted_boys):
        print_result += f"{boy} и {sorted_girls[index]}\n"

    return print_result


if __name__ == '__main__':
    print(get_medium_char('test'))
    print(get_medium_char('одинаковыми'))

    boys = ['Peter', 'Alex', 'John', 'Arthur', 'Richard']
    girls = ['Kate', 'Liza', 'Kira', 'Emma', 'Trisha']
    print(create_pairs(boys, girls))
