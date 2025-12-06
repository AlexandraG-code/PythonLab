import requests
import time


def interact_with_gruyere():
    base_url = "http://localhost:8008"
    session = requests.Session()

    # 1. Посетить главную страницу
    print("1. Visiting main page...")
    response = session.get(base_url)
    print(f"Status: {response.status_code}")

    # 2. Зарегистрировать нового пользователя
    print("2. Registering new user...")
    register_data = {
        'action': 'register',
        'username': f'test_user_{int(time.time())}',
        'password': 'test123',
        'password2': 'test123'
    }
    response = session.post(f"{base_url}/signup", data=register_data)

    # 3. Войти в систему
    print("3. Logging in...")
    login_data = {
        'action': 'login',
        'username': register_data['username'],
        'password': register_data['password']
    }
    response = session.post(f"{base_url}/login", data=login_data)

    # 4. Создать сниппет
    print("4. Creating snippet...")
    snippet_data = {
        'snippet': 'Test snippet for analysis',
        'action': 'save'
    }
    response = session.post(f"{base_url}/snippets.gtl", data=snippet_data)


if __name__ == "__main__":
    interact_with_gruyere()