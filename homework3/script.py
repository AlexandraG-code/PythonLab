import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Этап 1: Подготовка данных
file_path = 'events.json'  # Укажите путь к файлу events.json
with open(file_path, 'r') as f:
    data = pd.json_normalize(pd.read_json(f)['events'])

# Проверка доступных столбцов
print("Доступные столбцы:", data.columns)

# Этап 2: Анализ данных
if 'signature' in data.columns:
    signature_distribution = data['signature'].value_counts()
    print("Распределение типов событий:")
    print(signature_distribution)
else:
    print("Столбец 'signature' не найден в DataFrame.")

# Визуализация данных
if 'signature' in data.columns:
    plt.figure(figsize=(12, 6))
    sns.countplot(y='signature', data=data, order=data['signature'].value_counts().index)
    plt.title('Распределение типов событий информационной безопасности')
    plt.xlabel('Количество событий')
    plt.ylabel('Тип события')
    plt.show()
