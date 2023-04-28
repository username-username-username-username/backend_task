Для работы кода необходимо установить следующие библиотеки в окружение через которое будет запускаться код:
pip3 install fastapi
pip3 install SQLAlchemy
pip3 install mysql-connector-python#драйвер который используется в коде программы
pip3 install pyjwt

Также в коде необходимо перепроверить значения login и password (глобальные переменные) для подключения к СУБД и наличие установленной СУБД и драйвера "mysql-connector-python".

По умолчанию в коде программы объявлено 2 записи о пользователях:
add_user("TestLogin", "TestPassword", user_role_value="admin")#запись с ролью admin
add_user("PlsRemoveME", "my_super_password")#запись с ролью user пользователя

Для выполнения запросов на добавление пользователей или удаления, необходимо сначала пройти аутенфикацию и получить токен.
Для этого необходимо отправить POST запрос содержащий данные в JSON формате по следующему ip (для uvicorn):
http://127.0.0.1:8000/authentication/login
Данные:
{
    "login": "TestLogin",
    "password": "TestPassword"
}

В ответ сервер вернёт jwt токен:
{
    "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2xvZ2luIjoiVGVzdExvZ2luIiwidXNlcl9wd2RoYXNoIjoiN2JjZjlkODkyOThmMWJmYWUxNmZhMDJlZDZiNjE5MDhmZDJmYThkZTQ1ZGQ4ZTIxNTNhM2M0NzMwMDc2NTMyOCIsImV4cCI6MTY4Mjc0ODE0OX0.IqB5MlC10arJgul-7Et815xpxApnAkGZ8BqwxkOuMLk"
}

При отправке запроса на удаление пользователя или добавления, необходимо задать полю Authorization заголовку запроса значение jwt токена.
В Postman для этого можно выбрать Type API Key вкладки Authorization запроса и в поле value ввести ключ, убедившись, что поле key = Authorization.

http://127.0.0.1:8000/services/remove_user
{
    "login": "PlsRemoveME"
}

Пример ответа:
{
    "message": "удаление прошло успешно"
}

Для запроса о добавлении пользователя:
http://127.0.0.1:8000/services/add_user
Структура Body запроса выглядит следующим образом:
{
    "login": "q2121eht345TTTq",
    "password": "11111112345679",
    "email": "",
    "role": "user"
}

Значение поля email необязательное и можно оставить пустые кавычки.

pip3 install uvicorn#для запуска сервера (необязательно), можно использовать что-то другое

В репозитории также был добавлен файл коллекции запросов для Postman, импортировав которую можно будет провести тесты, запросы отправляются на ip: http://127.0.0.1:8000
Так как тестировались вместе с uvicorn.
