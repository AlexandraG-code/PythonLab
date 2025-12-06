from typing import TypedDict, List

import requests

#типизируем посты
class Post(TypedDict):
    userId:int
    title:str
    body:str

# ========= Задание 1 =========


def show_post_data(api_url, limit: int)-> None:
    """
    :param api_url: адрес апи
    :param limit: количество элементов, информацию о которых нужно вывести
    """
    post_data: List[Post] = requests.get(api_url).json()

    for index, post in enumerate(post_data):
        if (index > limit):
            break

        print(f"Заголовок: {post['title']}.\nОписание: {post['body']}\n\n")


# ========= Задание 2 =========

def get_weather_by_city(city: str, limit: int):

    """
    :param city: название города
    :param limit: крличество записей
    """

    API_KEY = "17d9111b7d0a4fc34dc507e946b88a87"
    API_URL = f"http://api.openweathermap.org/geo/1.0/direct?q={city}&limit={limit}&appid={API_KEY}"

    return requests.get(API_URL).json()



if __name__ == '__main__':
    show_post_data("https://jsonplaceholder.typicode.com/posts", 5 )
    print(get_weather_by_city('London', 5))