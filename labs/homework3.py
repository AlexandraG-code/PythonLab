from datetime import datetime, timedelta


# ================== Задание 1 ==================

# The Moscow Times - Wednesday, October 2, 2002
moscow_times = "Wednesday, October 2, 2002"
dt1 = datetime.strptime(moscow_times, "%A, %B %d, %Y")
print(f"The Moscow Times: {dt1}")

# The Guardian - Friday, 11.10.13
guardian = "Friday, 11.10.13"
dt2 = datetime.strptime(guardian, "%A, %d.%m.%y")
print(f"The Guardian: {dt2}")

# Daily News - Thursday, 18 August 1977
daily_news = "Thursday, 18 August 1977"
dt3 = datetime.strptime(daily_news, "%A, %d %B %Y")
print(f"Daily News: {dt3}")

# ================== Задание 2 ==================


def date_range(start_date, end_date):
    """
    Возвращает список дат за период от start_date до end_date.
    Даты должны вводиться в формате YYYY-MM-DD.
    При неверном формате или start_date > end_date возвращает пустой список.
    """
    try:
        # Пытаемся преобразовать строки в даты
        start = datetime.strptime(start_date, "%Y-%m-%d")
        end = datetime.strptime(end_date, "%Y-%m-%d")

        # Проверяем, что start_date не больше end_date
        if start > end:
            return []

        # Генерируем список дат
        date_list = []
        current_date = start
        while current_date <= end:
            date_list.append(current_date.strftime("%Y-%m-%d"))
            current_date += timedelta(days=1)

        return date_list

    except ValueError:
        # Если формат даты неверный
        return []




print("Тест 1:", date_range('2022-01-01', '2022-01-03'))
print("Тест 2:", date_range('2022-01-03', '2022-01-01'))
print("Тест 3:", date_range('2022-02-30', '2022-02-31'))