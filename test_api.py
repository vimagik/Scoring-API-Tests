import pytest
import datetime
import hashlib

import api
import store

TOKEN = "e98d4c34b7c6b6b6c73a470b5d36017d2a0f6735b2cd764562c6dd80819f74c77dffc1f8d85036079e08f2bd7e48eea2904b9419e322214cba0c5f7c4e50f137"


class MockStore:
    """Mock для Store"""

    def cache_get(*args, **kwargs):
        return None

    def cache_set(*args, **kwargs):
        pass

    def get(*args, **kwargs):
        return []


class MockStoreError:
    """Mock для Store с эффектом неработающего сервиса"""

    def get(*args, **kwargs):
        raise ConnectionRefusedError


@pytest.fixture
def mock_store(monkeypatch):

    def mock_set(*args, **kwargs):
        return MockStore()

    monkeypatch.setattr(store, 'Store', mock_set)


@pytest.fixture
def mock_store_error(monkeypatch):

    def mock_set(*args, **kwargs):
        return MockStoreError()

    monkeypatch.setattr(store, 'Store', mock_set)


def get_response(mock_store, request, context={}):
    response = api.method_handler(
        request=dict(body=request, headers={}),
        ctx=context,
        store=store.Store(
            parameters=('localhost', 11211),
            connect_attempts=5,
            timeout=1,
        ),
    )
    return response


def valid_auth_for_admin():
    return hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + api.ADMIN_SALT).encode('utf-8')).hexdigest()


def test_invalid_char():
    value = api.CharField(required=True, nullable=False)
    value.name = 'chr'
    with pytest.raises(api.ValidationError):
        value.__set__(value, 123)


def test_invalid_argument_field():
    value = api.ArgumentsField(required=True, nullable=False)
    value.name = 'argument'
    with pytest.raises(api.ValidationError):
        value.__set__(value, 123)


def test_invalid_email_field():
    value = api.EmailField(required=True, nullable=False)
    value.name = 'email'
    with pytest.raises(api.ValidationError):
        value.__set__(value, '123123.ru')


def test_invalid_phone_field():
    value = api.PhoneField(required=True, nullable=False)
    value.name = 'phone'
    with pytest.raises(api.ValidationError):
        value.__set__(value, '89111231212')
    with pytest.raises(api.ValidationError):
        value.__set__(value, '7911123121212')


def test_invalid_date_field():
    value = api.DateField(required=True, nullable=False)
    value.name = 'date'
    with pytest.raises(ValueError):
        value.__set__(value, '2020.12.12')


def test_invalid_birthday():
    value = api.BirthDayField(required=True, nullable=False)
    value.name = 'birthday'
    with pytest.raises(ValueError):
        value.__set__(value, '2020.12.12')
    with pytest.raises(api.ValidationError):
        value.__set__(value, '01.01.1900')


def test_invalid_gender():
    value = api.GenderField(required=True, nullable=False)
    value.name = 'gender'
    with pytest.raises(api.ValidationError):
        value.__set__(value, 4)
    with pytest.raises(api.ValidationError):
        value.__set__(value, 'str')


def test_invalid_clients_id():
    value = api.ClientIDsField(required=True)
    value.name = 'cid'
    with pytest.raises(api.ValidationError):
        value.__set__(value, {1, 2, 3})
    with pytest.raises(api.ValidationError):
        value.__set__(value, [1, '2', 3])


def test_empty_request(mock_store):
    _, code = get_response(mock_store, {})
    assert api.INVALID_REQUEST == code


@pytest.mark.parametrize(
    'request_json',
    [
        {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "", "arguments": {}},
        {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "sdd", "arguments": {}},
        {"account": "horns&hoofs", "login": "admin", "method": "online_score", "token": "", "arguments": {}},
    ]
)
def test_bad_auth(mock_store, request_json):
    _, code = get_response(mock_store, request_json)
    assert api.FORBIDDEN == code


@pytest.mark.parametrize(
    'request_response',
    [
        ({"account": "horns&hoofs", "login": 123, "method": "online_score"}, 'login must be Str'),
        ({"account": "horns&hoofs", "login": '456', "arguments": {}}, "'token'"),
        ({"account": "horns&hoofs", "method": "online_score", "arguments": {}}, "'login'"),
    ]
)
def test_invalid_request_code(mock_store, request_response):
    request_json, response_valid = request_response
    response, code = get_response(mock_store, request_json)
    assert api.INVALID_REQUEST == code
    assert response_valid == response


@pytest.mark.parametrize(
    'arguments_response',
    [
        ({"phone": "79998887766"}, 'Not enough data in arguments'),
        ({"phone": "89998887766", "email": "test@test.ru"}, 'phone must have 7 in the start of value'),
        ({"phone": "79998887766", "email": "testtest.ru"}, 'email must have @'),
        ({"phone": "79998887766", "email": "test@test.ru", "gender": -1}, 'gender must be 0, 1, 2 or None'),
        ({"phone": "79998887766", "email": "test@test.ru", "gender": "1"}, 'gender must be int'),
        ({"phone": "79998887766", "email": "test@test.ru", "gender": 1, "birthday": "01.01.1890"},
         'birthday is less then 70'),
        ({"phone": "79998887766", "email": "test@test.ru", "gender": 1, "birthday": "XXX"},
         "time data 'XXX' does not match format '%d.%m.%Y'"),
        ({"phone": "79998887766", "email": "test@test.ru", "gender": 1, "birthday": "01.01.2000", "first_name": 1},
         'first_name must be Str'),
        ({"phone": "79998887766", "email": "test@test.ru", "gender": 1, "birthday": "01.01.2000",
          "first_name": "s", "last_name": 2}, 'last_name must be Str'),
        ({"phone": "79998887766", "birthday": "01.01.2000", "first_name": "s"}, 'Not enough data in arguments'),
    ]
)
def test_invalid_score_request(mock_store, arguments_response):
    arguments, response_valid = arguments_response
    request_json = {
        "account": "test",
        "login": "tst",
        "method": "online_score",
        "token": TOKEN,
        "arguments": arguments
    }
    response, code = get_response(mock_store, request_json)
    assert api.INVALID_REQUEST == code
    assert response_valid == response


@pytest.mark.parametrize(
    'arguments_score',
    [
        ({"phone": "79998887766", "email": "test@test.ru"}, 3),
        ({"phone": 79998887766, "email": "test@test.ru"}, 3),
        ({"gender": 1, "birthday": "01.01.1991", "first_name": "a", "last_name": "b"}, 2),
        ({"gender": 0, "birthday": "01.01.1991"}, 0),
        ({"first_name": "a", "last_name": "b"}, 0.5),
        ({"phone": "79998887766", "email": "test@test.ru", "gender": 1, "birthday": "01.01.1991",
         "first_name": "a", "last_name": "b"}, 5),
    ]
)
def test_valid_score_request(mock_store, arguments_score):
    arguments, score_valid = arguments_score
    request_json = {
        "account": "test",
        "login": "tst",
        "method": "online_score",
        "token": TOKEN,
        "arguments": arguments
    }
    context = {}
    response, code = get_response(mock_store, request_json, context)
    score = response.get('score')
    assert api.OK == code
    assert score_valid == score
    assert sorted(context['has']) == sorted(arguments.keys())


def test_valid_score_request_for_admin(mock_store):
    arguments = {"phone": "79998887766", "email": "test@test.ru"}
    request_json = {
        "account": "test",
        "login": "admin",
        "method": "online_score",
        "token": valid_auth_for_admin(),
        "arguments": arguments
    }
    context = {}
    response, code = get_response(mock_store, request_json, context)
    score = response.get('score')
    assert api.OK == code
    assert 42 == score
    assert sorted(context['has']) == sorted(arguments.keys())


@pytest.mark.parametrize(
    'arguments_response',
    [
        ({}, "'client_ids'"),
        ({"date": "01.01.1991"}, "'client_ids'"),
        ({"client_ids": [], "date": "01.01.1991"}, 'Client Id can have digit only'),
        ({"client_ids": {1: 2}, "date": "01.01.1991"}, 'Client Id must be List'),
        ({"client_ids": ["1", "2"], "date": "01.01.1991"}, 'Client Id can have digit only'),
        ({"client_ids": [1, 2], "date": "123"}, "time data '123' does not match format '%d.%m.%Y'"),
    ]
)
def test_invalid_interest_request(mock_store, arguments_response):
    arguments, response_valid = arguments_response
    request_json = {
        "account": "test",
        "login": "tst",
        "method": "clients_interests",
        "token": TOKEN,
        "arguments": arguments
    }
    response, code = get_response(mock_store, request_json)
    assert api.INVALID_REQUEST == code
    assert response_valid == response


@pytest.mark.parametrize(
    'arguments',
    [
        {"client_ids": [1, 2, 3], "date": datetime.datetime.today().strftime("%d.%m.%Y")},
        {"client_ids": [1, 2], "date": "01.01.1991"},
        {"client_ids": [0]},
    ]
)
def test_valid_interest_request(mock_store, arguments):
    arguments = arguments
    request_json = {
        "account": "test",
        "login": "tst",
        "method": "clients_interests",
        "token": TOKEN,
        "arguments": arguments
    }
    context = {}
    response, code = get_response(mock_store, request_json, context)
    assert api.OK == code
    assert len(arguments["client_ids"]) == len(response)
    assert context["nclients"] == len(arguments["client_ids"])
    assert (isinstance(response[key], list) for key in arguments["client_ids"])
    assert ((isinstance(value, str) for value in response[key]) for key in arguments["client_ids"])


def test_valid_interest_request_with_server_error(mock_store_error):
    request_json = {
        "account": "test",
        "login": "tst",
        "method": "clients_interests",
        "token": TOKEN,
        "arguments": {"client_ids": [1, 2], "date": "01.01.1991"}
    }
    with pytest.raises(ConnectionRefusedError):
        get_response(mock_store_error, request_json)
