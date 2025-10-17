def sum_distance(start: int, to: int) -> int:
    # создаем диапазон чисел
    int_range: list[int] = [start, to] if start < to else [to, start]
    # число с которого начнется сумиирование
    count: int = int_range[0]
    result_sum: int = 0

    while count <= int_range[1]:
        result_sum += count
        count += 1

    return result_sum


def trim_and_repeat(string: str, offset: int = 0, repetitions: int = 1) -> str:
    # рез строки с учетом смещения
    str_slice: str = string[offset:]

    # Используем умножение строки для повторения
    return str_slice * repetitions


if __name__ == '__main__':
    print(sum_distance(7, 2))

    print(trim_and_repeat('testic', 3, 2))
