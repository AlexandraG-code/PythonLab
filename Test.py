import re


def check_email(email: str) -> bool:
    email_pattern = r'(\.|@)+[^\s]*'

    have_match = re.match(email_pattern, email)

    return have_match is not None


def longest_film(film_1: str, film_2: str,film_3: str) -> str:
    film_list= [film_1, film_2, film_3]

    length = 0
    for film in film_list:
        film_length = len(film)
        if(length < film_length):
            length = film_length
        else:
            length += 1



if __name__ == '__main__':
    t = check_email('Helloworld@.ru')   is True
    print(t)
    t2 = check_email('python@email@net') is True
    print(t2)
