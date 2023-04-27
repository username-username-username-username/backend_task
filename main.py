from fastapi import FastAPI, Response, Request#для обработки api запросов
from pydantic import BaseModel
import json
import re#для проверки текстовых значений полей

from hashlib import sha256#для хэширования паролей
from sqlalchemy import create_engine, text, insert, select, delete, MetaData, Table, Integer, String, Column#для работы с бд
import sys#для самостоятельного аварийного закрытия программы до краша, если не удалось подключиться к СУБД...
import atexit#для последующего закрытия соединения с менеджером подключений к бд (необязательно)
import jwt#для создания и декодирования подписанных jwt токенов
import datetime#для получения текущего unix времени для ограничения токенов по времени

#глобальные переменные:
default_valid_characters_set = r"""[A-Za-z0-9!"#$%&'()*+,-.\/:;<=>?@[\]^_`{|}~]"""#regex для проверки полей логина, пароля, роли
email_valid_characters_set = r'\b[A-Za-z0-9.]+@[A-Za-z0-9.]+\.[A-Z|a-z.]{2,7}\b'#regex для проверки поля email
secret_key = "01d25e094faa6ea2556c818166b2a9563b93f7094f6f0f4caa6cf63b88e8d3e5"#ключ для подписи JWT токена
jwt_exp_timezone = datetime.timezone.utc
jwt_life_duration = datetime.timedelta(hours=24)
#переменные для подключения к СУБД
login = "root" #возможно необходимо в дальнейшем спрятать данные для подключения к субд mysql вне основного кода, в отдельном файле
password = "mySQL_root_passsssword4576"
host = "127.0.0.1"
port = "3306"

dbname = "backend_db" #название БД для хранения таблицы, будет создана автоматически, если не существует
engine = None
users = None

def execute_connection_statement(statement):
    """функция для запуска переданных ей запросов к инициализированной переменной engine\n

    parameters:\n
    statement (text): sql запрос
    """
    connection = engine.connect()
    result = connection.execute(statement)
    connection.commit()
    connection.close()
    return result

def db_initialization():
    """функция для инициализации бд и таблицы\n"""
    global engine
    global users
    try:
        engine = create_engine("mysql+mysqlconnector://" + login + ":" + password + "@" + host + ":" + port)#подключение к субд
        connection = engine.connect()#проверка соединения
        connection.close()
        print("Успешное подключение к СУБД")
    except:
        print("Не удалось подключиться к СУБД")#необходимо проверить значения глобальных переменных
        sys.exit()

    #execute_connection_statement(text("drop database if  exists `" + dbname + "`;")) #удалить бд (нужно было для тестов)
    
    #создание бд с dbname, если ещё не создана и проверка установленной кодировки (без поддержки кириллицы, по заданию...)
    execute_connection_statement(text("create database if not exists `" + dbname + "` default character set = ascii collate = ascii_bin;"))
    execute_connection_statement(text("alter database " + dbname + " character set ascii collate ascii_bin;"))
    engine.dispose()#отключение от субд в целом и подключение к теперь уже наверняка существующей бд
    engine = create_engine("mysql+mysqlconnector://" + login + ":" + password + "@" + host + ":" + port + "/" + dbname)

    #создание таблицы, если она ещё не была создана
    connection = engine.connect()
    metadata = MetaData()
    users = Table('users', metadata,
        Column('user_id', Integer(), nullable=False, autoincrement=True, primary_key=True),
        Column('user_login', String(20), nullable=False, unique=True),
        Column('user_pwdhash', String(64), nullable=False),
        Column('user_email', String(255), nullable=True, unique=True),
        Column('user_role', String(255), nullable=False)
    )
    metadata.create_all(engine)
    connection.commit()
    connection.close()

def add_user(user_login_value, user_password_value, user_email_value = None, user_role_value = "user"):
    """функция для добавления записи о пользователе в бд, на вход принимает уже подготовленные ранее правильные значения, так как не содержит собственных проверок\n
    значение целочисленного поля-первичного ключа user_id заполняется автоматически (autoincrement)\n

    parameters:\n
    user_login_value (string): логин пользователя для хранения в поле user_login\n
    user_password_value (string): пароль пользователя для хранения хэша в поле user_pwdhash\n
    user_email_value (string): email пользователя для хранения в поле user_email (необязательное поле)\n
    user_role_value (string): роль пользователя для хранения в поле user_role (значение по умолчанию "user")
    """
    password_hash = sha256(user_password_value.encode('utf-8')).hexdigest()
    statement = insert(users).values(user_login = user_login_value, user_pwdhash = password_hash, user_email = user_email_value, user_role = user_role_value)
    result = execute_connection_statement(statement)
    print("была добавлена новая запись о пользователе со значение user_id: " + str(result.inserted_primary_key[0]))

def remove_user(user_login_value):
    """функция для удаления записи о пользователе в бд, на вход принимает уже подготовленные ранее правильные значения, так как не содержит собственных проверок\n

    parameters:\n
    user_login_value (string): логин пользователя для удаления
    """
    statement = delete(users).where(users.c.user_login == user_login_value)
    result = execute_connection_statement(statement)
    print("было удалено: " + str(result.rowcount) + " пользователей с логином: " + user_login_value)

def login_exists(user_login_value):
    """функция для проверки того, существуют ли записи с данным login\n

    parameters:\n
    user_login_value (string): логин пользователя для проверки
    """
    statement = select(users).where(users.c.user_login == user_login_value)
    result = execute_connection_statement(statement)
    print("было найдено: " + str(result.rowcount) + " пользователей с логином: " + user_login_value)
    if (result.rowcount >= 1):
        return True
    return False

def email_exists(user_email_value):
    """функция для проверки того, существуют ли записи с данным email\n

    parameters:\n
    user_email_value (string): email пользователя для проверки
    """
    statement = select(users).where(users.c.user_email == user_email_value)
    result = execute_connection_statement(statement)
    print("было найдено: " + str(result.rowcount) + " пользователей с email: " + user_email_value + "/")
    if (result.rowcount >= 1):
            return True
    return False

def get_user_pwdhash_and_role_by_login(user_login_value):
    """функция для считывания хэша пароля и роли пользователя, если запись о пользователе существует\n

    parameters:\n
    user_login_value (string): значение поля user_login пользователя для которой будет произведено считывание данных полей: user_pwdhash и user_role\n

    returns:\n
    (list): список содержащий последовательно 2 значения: user_pwdhash_value, user_role_value. если значения не будут найдены, будут подставлены None
    """
    user_pwdhash_value = None
    user_role_value = None
    statement = select(users.columns["user_pwdhash"], users.columns["user_role"]).where(users.c.user_login == user_login_value)
    result = execute_connection_statement(statement)
    for row in result:
        user_pwdhash_value = row[0]
        user_role_value = row[1]
    if (result.rowcount >= 1):
        print("успешное чтение значений pwdhash и role для пользователя с логином: " + user_login_value)
    else:
        print("не удалось прочитать значения pwdhash и role для пользователя с логином: " + user_login_value + ", так как пользователь не был найден")
    return [user_pwdhash_value, user_role_value]

def string_valid(string_for_check, min_length, max_length, valid_characters_set = default_valid_characters_set):
    """функция для проверки значений текстовых полей\n

    parameters:\n
    string_for_check (str): строка для проверки\n
    min_length (int): минимальная длина\n
    max_length (int): максимальная длина\n
    valid_characters_set (regex str): regex строка для проверки на наличие только разрешённых символов (значение поля задано по умолчанию). Для проверки почты используется глобальная переменная email_valid_characters_set\n

    returns:\n
    (Response): в основном, json объект содержащий поле "message" содержащее сведения о результате или ошибке и status_code ответа
    """
    if not ((len(string_for_check) >= min_length) and (len(string_for_check) <= max_length)):#проверка длины
        return False
    if not (len(string_for_check) == 0):#поле может оставлено пустым, например email
        if not re.match(valid_characters_set, string_for_check):
            print("не соответствует regex")
            return False
    #проверка на наличие символов кроме разрешённых в строке regex valid_characters_set
    return True

db_initialization()#инициализация бд и таблицы
if (login_exists("TestLogin") == False):#проверка, что login не занят
    add_user("TestLogin", "TestPassword", user_role_value="admin")#добавления пользователя с ролью admin для тестирования api запросов
if (login_exists("PlsRemoveME") == False):#проверка, что login не занят
    add_user("PlsRemoveME", "my_super_password")#добавления пользователя с ролью user для тестирования api запросов
    
app = FastAPI()

class authentication_user_structure(BaseModel):#структура input данных для post запроса на аутенфикацию по логину и паролю
    login: str
    password: str

@app.post("/authentication/login")
async def root(authentication_user: authentication_user_structure):
    """функция для обработки post запроса на аутенфикацию по логину и паролю\n

    parameters:\n
    authentication_user (authentication_user_structure): значения строковых полей login и password в виде JSON объекта\n

    returns:\n
    (Response): в основном, json объект содержащий поле "jwt" с токеном или сообщением об ошибке и status_code ответа
    """
    status_code_value = 401
    jwt_token = "что-то пошло не так"
    if string_valid(authentication_user.login, 6, 20):#если login соответствует правилам по длине и т.д. (не содержит символы кириллицы)
        if string_valid(authentication_user.password, 8, 20):#если password соответствует правилам по длине и т.д. (не содержит символы кириллицы)
            user_pwdhash_value = get_user_pwdhash_and_role_by_login(authentication_user.login)[0]#pwdhash
            if (user_pwdhash_value != None):#если пользователь найден
                new_password_hash = sha256(authentication_user.password.encode('utf-8')).hexdigest()
                if (user_pwdhash_value == new_password_hash):#хэши паролей совпадают
                    payload = {'user_login':authentication_user.login,'user_pwdhash':user_pwdhash_value, 'exp':datetime.datetime.now(jwt_exp_timezone) + jwt_life_duration}
                    jwt_token = jwt.encode(payload, secret_key, algorithm="HS256")#будет возвращён сгенерированный токен
                    status_code_value = 200
                else:
                    jwt_token = "пароль неправильный"
            else:
                jwt_token = "пользователь не найден"
        else:
            status_code_value = 400
            jwt_token = "длина значения типа строки для поля password не менее 8 символов и не более 20. Разрешено использовать только символы соответствующее regex: " + default_valid_characters_set
    else:
        status_code_value = 400
        jwt_token = "длина значения типа строки для поля login не менее 6 символов и не более 20. Разрешено использовать только символы соответствующее regex: " + default_valid_characters_set
    result = {"jwt": jwt_token}
    return Response(content=json.dumps(result), media_type="application/json", status_code=status_code_value)

def verify_jwt_token_and_return_role(encoded_jwt):
    """функция для проверки jwt токена и возвращения роли пользователя, если токен правильный\n

    parameters:\n
    encoded_jwt (string): закодированный (подписанный) jwt токен\n

    returns:\n
    (bool): False -> если возникла ошибка при чтении токена, либо если пользователь с данным токеном не найден (уже удален или не существовал), например администратор может удалить собственный аккаунт
    и при повторном запросе не сможет пройти авторизацию, так как записи о нём больше не будет и не с чем будет сравнивать хэш пароля из токена.\n
    (string): user_role, если пользователь с логином из токена ещё существует и хэш пароля из токена равен хэшу пароля в записи бд
    """
    try:
        decoded_jwt = jwt.decode(encoded_jwt, secret_key, algorithms=["HS256"])
        user_login_value = decoded_jwt["user_login"]
        if login_exists(user_login_value):
            user_pwdhash_value_from_token = decoded_jwt["user_pwdhash"]
            result = get_user_pwdhash_and_role_by_login(user_login_value)
            user_pwdhash_value_stored = result[0]
            user_role_value = result[1]
            if (user_pwdhash_value_from_token == user_pwdhash_value_stored):
                return user_role_value
    except:
        return False
    return False

class removing_user_structure(BaseModel):#структура input данных для post запроса на удаление пользователя
    login: str

@app.post("/services/remove_user")
async def root(removing_user: removing_user_structure, req: Request):
    """функция для обработки post запроса на удаление пользователя\n

    parameters:\n
    removing_user (removing_user_structure): значения строкового поля login в виде JSON объекта\n

    returns:\n
    (Response): в основном, json объект содержащий поле "message" содержащее сведения о результате или ошибке и status_code ответа
    """
    status_code_value = 401
    if (req.headers.__contains__("Authorization")):#проверка что поле для токена присутствует в заголовке запроса
        encoded_jwt = str(req.headers["Authorization"])
        user_role_value = verify_jwt_token_and_return_role(encoded_jwt)
        if (user_role_value != False):
            if (user_role_value == "admin"):
                if string_valid(removing_user.login, 6, 20):#если login соответствует правилам по длине и т.д. (не содержит символы кириллицы)
                    remove_user(str(removing_user.login))
                    message = "удаление прошло успешно"
                    status_code_value = 200
                else:
                    message = "длина значения типа строки для поля login не менее 6 символов и не более 20. Разрешено использовать только символы соответствующее regex: " + default_valid_characters_set
                    status_code_value = 400
            else:
                message = "недостаточно прав для удаления пользователей"
                status_code_value = 403
        else:
            message = "jwt токен неправильный (возможно устарел), либо что-то ещё пошло не так"
        result = {
            "message": message
        }
        return Response(content=json.dumps(result), media_type="application/json", status_code=status_code_value)
    else:
        return Response(content=json.dumps({"message": "для выполнения запроса необходимо задать значение JWT токена в поле 'Authorization' заголовка запроса "}), media_type="application/json", status_code=status_code_value)

class adding_user_structure(BaseModel):#структура input данных для post запроса на добавление пользователя
    login: str
    password: str
    email: str#необязательное поле, можно передать пустые кавычки
    role: str

@app.post("/services/add_user")
async def root(adding_user: adding_user_structure, req: Request):
    """функция для обработки post запроса на удаление пользователя\n

    parameters:\n
    adding_user (adding_user_structure): значения строковых полей: login, passwprd, email, role в виде JSON объекта. Значение поля email необязательно и можно оставить пустые кавычки ""\n

    returns:\n
    (Response): в основном, json объект содержащий поле "message" содержащее сведения о результате или ошибке и status_code ответа
    """
    status_code_value = 400
    if (req.headers.__contains__("Authorization")):#проверка что поле для токена присутствует в заголовке запроса
        encoded_jwt = str(req.headers["Authorization"])
        message = "добавление прошло успешно"
        user_role_value = verify_jwt_token_and_return_role(encoded_jwt)
        if (user_role_value != False):
            if (user_role_value == "admin"):
                if string_valid(adding_user.login, 6, 20):#если login соответствует правилам по длине и т.д. (не содержит символы кириллицы)
                    if string_valid(adding_user.password, 8, 20):#если password соответствует правилам и т.д. (не содержит символы кириллицы)
                        if string_valid(adding_user.role, 0, 255):#если role соответствует правилам и т.д. (не содержит символы кириллицы)
                            if not login_exists(adding_user.login):
                                if (len(adding_user.email) >= 3):#если значение для поля email передано, так как поле необязательное
                                    if string_valid(adding_user.email, 0, 255, email_valid_characters_set):#если email соответствует правилам и т.д. (не содержит символы кириллицы)
                                        if not email_exists(adding_user.email):#если email не занят
                                            add_user(str(adding_user.login), str(adding_user.password), str(adding_user.email), str(adding_user.role))
                                            status_code_value = 200
                                        else:
                                            message = "данный email уже занят"
                                    else:
                                        message = "длина значения типа строки для поля email не менее 0 символов и не более 255. Разрешено использовать только символы соответствующее regex: " + email_valid_characters_set 
                                else:#если значение для поля email не передано, то при добавлении записи в таблицу бд, это поле пропускается
                                    add_user(str(adding_user.login), str(adding_user.password), user_role_value=str(adding_user.role))
                                    status_code_value = 200
                            else:
                                message = "данный login уже занят"#                  ^             ^             ^             ^             ^             ^             ^             ^             ^
                        else:#/\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\           /#\           /#\           /#\           /#\           /#\           /#\           /#\           /#\           /#\
                            message = "длина значения типа строки для поля role не менее 0 символов и не более 255. Разрешено использовать только символы соответствующее regex: " + default_valid_characters_set
                    else:#  /____\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\        /####\        /####\        /####\        /####\        /####\        /####\        /####\        /####\        /####\
                        message = "длина значения типа строки для поля password не менее 8 символов и не более 20. Разрешено использовать только символы соответствующее regex: " + default_valid_characters_set
                else:#     |======||============\\\\\\\====================#      /######\      /######\      /######\      /######\      /######\      /######\      /######\      /######\      /######\
                    message = "длина значения типа строки для поля login не менее 6 символов и не более 20. Разрешено использовать только символы соответствующее regex: " + default_valid_characters_set
            else:#         |      ||            ||    ||                   #     /########\    /########\    /########\    /########\    /########\    /########\    /########\    /########\    /########\
                message = "недостаточно прав для добавления пользователей" #         ||            ||            ||            ||            ||            ||            ||            ||            ||
                status_code_value = 403#        ||*   ||                   #         ||            ||            ||            ||            ||            ||            ||            ||            ||
        else:#/____________|______||____________||____||___________________#_________||____________||____________||____________||____________||____________||____________||____________||____________||_____
            message = "jwt токен неправильный (возможно устарел), либо что-то ещё пошло не так"
        result = {
            "message": message
        }
        return Response(content=json.dumps(result), media_type="application/json", status_code=status_code_value)
    else:
        status_code_value = 401
        return Response(content=json.dumps({"message": "для выполнения запроса необходим jwt токен в поле 'authorization' заголовка запроса "}), media_type="application/json", status_code=status_code_value)

#завершение работы последнего движка запросов (переменной) при завершении работы программы, так как для каждого create_engine, нужно сделать engine.dispose...
atexit.register(engine.dispose)
atexit.register(print, 'завершение работы программы')