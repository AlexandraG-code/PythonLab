import pandas as pd

file_path = 'botsv1.json'

security_logs = pd.read_json(file_path)
# Извлечение данных из колонки 'result'
expanded_security_logs = pd.json_normalize(security_logs['result'])

failed_login_codes = ['4625', '4771', '4771']
privilege_escalation = ['4672', '4104', '4688', '4688']
users_event = ['4720', '4722', '4724', '4728', '4703']
# Список подозрительных EventCode в виде строк
suspicious_event_codes = [*failed_login_codes, *privilege_escalation, *users_event ]
# Фильтрация записей, содержащих подозрительные EventCode
suspicious_logs = expanded_security_logs[expanded_security_logs['EventCode'].isin(suspicious_event_codes)]
# Анализ данных
event_counts = suspicious_logs['EventCode'].value_counts()


df = pd.read_parquet('dns.parquet')
print(df.columns.tolist())

print(event_counts)
