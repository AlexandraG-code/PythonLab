import webbrowser
import time

# Открываем Gruyere
webbrowser.open("https://google-gruyere.appspot.com/")

# Даем время для взаимодействия
print("Взаимодействуйте с сайтом в течение 60 секунд...")
time.sleep(60)

# Генерируем отчет
analyzer.generate_report()