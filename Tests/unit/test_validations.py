import pytest
import datetime

from API import api


@pytest.mark.parametrize(
    'test_value',
    [
        (123, True),
        ([1, 2, 3], True),
        ({1: 1, 2: 2}, False),
        (None, False)
    ]
)
def test_invalid_char(test_value):
    input_parameter, nullable = test_value
    value = api.CharField(required=True, nullable=nullable)
    value.name = 'chr'
    with pytest.raises(api.ValidationError):
        value.__set__(value, input_parameter)


def test_valid_char():
    value = api.CharField(required=True, nullable=False)
    value.name = 'chr'
    value.__set__(value, 'string')
    assert value.data[value] == 'string'


@pytest.mark.parametrize(
    'test_value',
    [
        (123, True),
        ([1, 2, 3], True),
        ((1, 2, 3), False),
        (None, False),
    ]
)
def test_invalid_argument_field(test_value):
    input_parameter, nullable = test_value
    value = api.ArgumentsField(required=True, nullable=nullable)
    value.name = 'argument'
    with pytest.raises(api.ValidationError):
        value.__set__(value, input_parameter)


def test_valid_argument_field():
    value = api.ArgumentsField(required=True, nullable=False)
    value.name = 'argument'
    value.__set__(value, {1: 1})
    assert value.data[value] == {1: 1}


@pytest.mark.parametrize(
    'test_value',
    [
        ('123123.ru', True),
        ([1, 2, 3], True),
        ((1, 2, 3), False),
        (None, False),
    ]
)
def test_invalid_email_field(test_value):
    input_parameter, nullable = test_value
    value = api.EmailField(required=False, nullable=nullable)
    value.name = 'email'
    with pytest.raises(api.ValidationError):
        value.__set__(value, input_parameter)


def test_valid_email_field():
    value = api.EmailField(required=False, nullable=False)
    value.name = 'email'
    value.__set__(value, '123@123.ru')
    assert value.data[value] == '123@123.ru'


@pytest.mark.parametrize(
    'test_value',
    [
        ('89111231212', True),
        ('7911123121212', True),
        ((1, 2, 3), False),
        (None, False),
    ]
)
def test_invalid_phone_field(test_value):
    input_parameter, nullable = test_value
    value = api.PhoneField(required=True, nullable=nullable)
    value.name = 'phone'
    with pytest.raises(api.ValidationError):
        value.__set__(value, input_parameter)


@pytest.mark.parametrize(
    'test_value',
    [
        ('79111231212', True),
        (79111231212, True),
        (None, True),
    ]
)
def test_valid_phone_field(test_value):
    input_parameter, nullable = test_value
    value = api.PhoneField(required=True, nullable=nullable)
    value.name = 'phone'
    value.__set__(value, input_parameter)
    assert value.data[value] == input_parameter


@pytest.mark.parametrize(
    'test_value',
    [
        ('2020.12.12', True),
        ([1, 2, 3], True),
        ((1, 2, 3), False),
        (None, False),
    ]
)
def test_invalid_date_field(test_value):
    input_parameter, nullable = test_value
    value = api.DateField(required=True, nullable=nullable)
    value.name = 'date'
    with pytest.raises(Exception):
        value.__set__(value, input_parameter)


def test_valid_date_field():
    value = api.DateField(required=True, nullable=True)
    value.name = 'date'
    value.__set__(value, '12.12.2010')
    assert value.data[value] == datetime.datetime(2010, 12, 12, 0, 0)


@pytest.mark.parametrize(
    'test_value',
    [
        ('2020.12.12', True),
        ('01.01.1900', True),
        ((1, 2, 3), False),
        (None, False),
    ]
)
def test_invalid_birthday(test_value):
    input_parameter, nullable = test_value
    value = api.BirthDayField(required=True, nullable=nullable)
    value.name = 'birthday'
    with pytest.raises(Exception):
        value.__set__(value, input_parameter)


def test_valid_birthday():
    value = api.BirthDayField(required=True, nullable=False)
    value.name = 'birthday'
    value.__set__(value, '12.12.2012')
    assert value.data[value] == datetime.datetime(2012, 12, 12, 0, 0)


@pytest.mark.parametrize(
    'test_value',
    [
        (4, True),
        ('str', True),
        ((1, 2, 3), False),
        (None, False),
    ]
)
def test_invalid_gender(test_value):
    input_parameter, nullable = test_value
    value = api.GenderField(required=True, nullable=nullable)
    value.name = 'gender'
    with pytest.raises(api.ValidationError):
        value.__set__(value, input_parameter)


def test_valid_gender():
    value = api.GenderField(required=True, nullable=False)
    value.name = 'gender'
    value.__set__(value, 2)
    assert value.data[value] == 2


@pytest.mark.parametrize(
    'test_value',
    [
        {1, 2, 3},
        [1, '2', 3],
        None,
    ]
)
def test_invalid_clients_id(test_value):
    value = api.ClientIDsField(required=True)
    value.name = 'cid'
    with pytest.raises(api.ValidationError):
        value.__set__(value, test_value)


def test_valid_clients_id():
    value = api.ClientIDsField(required=True)
    value.name = 'cid'
    value.__set__(value, [1, 2, 3])
    assert value.data[value] == [1, 2, 3]
