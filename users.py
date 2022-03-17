import argparse
import getpass
import hashlib
import hmac
import json
import os

import boto3
from boto3.dynamodb.types import Binary
from botocore.exceptions import ClientError


def get_table_name(stage: str) -> str:
    # We might want to user the chalice modules to
    # load the config.  For now we'll just load it directly.
    with open(os.path.join('.chalice', 'config.json')) as f:
        data = json.load(f)

    try:
        return data['stages'][stage]['environment_variables']['USERS_TABLE_NAME']  # stage
    except KeyError:
        return data['environment_variables']['USERS_TABLE_NAME']  # top-level


def create_user(stage: str) -> None:
    table_name = get_table_name(stage)
    table = boto3.resource('dynamodb').Table(table_name)
    username = input('Username: ').strip()
    password = getpass.getpass('Password: ').strip()
    password_fields = encode_password(password)
    item = {
        'username': username,
        'hash': password_fields['hash'],
        'salt': Binary(password_fields['salt']),
        'rounds': password_fields['rounds'],
        'hashed': Binary(password_fields['hashed']),
    }
    table.put_item(Item=item)


def encode_password(password: str, salt: bytes = None) -> dict:
    if salt is None:
        salt = os.urandom(16)
    rounds = 100000
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                                 salt, rounds)
    return {
        'hash': 'sha256',
        'salt': salt,
        'rounds': rounds,
        'hashed': hashed,
    }


def list_users(stage: str) -> None:
    table_name = get_table_name(stage)
    table = boto3.resource('dynamodb').Table(table_name)
    for item in table.scan()['Items']:
        print(item['username'])


def test_password(stage: str) -> None:
    username = input('Username: ').strip()
    password = getpass.getpass('Password: ').strip()
    table_name = get_table_name(stage)
    table = boto3.resource('dynamodb').Table(table_name)
    item = table.get_item(Key={'username': username})['Item']
    encoded = encode_password(password, salt=item['salt'].value)
    if hmac.compare_digest(encoded['hashed'], item['hashed'].value):
        print('Password verified.')
    else:
        print('Password verification failed.')


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--create-user', action='store_true')
    parser.add_argument('-t', '--test-password', action='store_true')
    parser.add_argument('-s', '--stage', default='dev')
    parser.add_argument('-l', '--list-users', action='store_true')
    args = parser.parse_args()

    if args.create_user:
        try:
            create_user(args.stage)
        except ClientError:
            print(f'AWS dynamodb table {get_table_name(args.stage)} does not exist!')
    elif args.list_users:
        list_users(args.stage)
    elif args.test_password:
        test_password(args.stage)


if __name__ == '__main__':
    main()
