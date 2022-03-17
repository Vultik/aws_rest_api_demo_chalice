import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from botocore.exceptions import ClientError
import jwt
from chalice import UnauthorizedError

from chalicelib.secrets_manager import get_secret

try:
    _SECRET = get_secret('JWT_SECRET_KEY')['JWT_SECRET_KEY']
except (ClientError, Exception):  # Exception for ChaliceDeploymentError
    _SECRET = 'my-super-duper-secret'  # for use without AWS Secrets Manager


def get_jwt_token(username: str, password: str, record: dict) -> Any:
    token_expiration = timedelta(minutes=30)

    actual = hashlib.pbkdf2_hmac(
        record['hash'],
        password.encode('utf-8'),
        record['salt'].value,
        record['rounds']
    )
    expected = record['hashed'].value
    if hmac.compare_digest(actual, expected):
        now = datetime.utcnow()
        unique_id = str(uuid4())
        payload = {
            'sub': username,
            'iat': now,
            'nbf': now,
            'jti': unique_id,
            'exp': datetime.utcnow() + token_expiration
        }

        return jwt.encode(payload, _SECRET, algorithm='HS256')

    raise UnauthorizedError('Invalid password')


def decode_jwt_token(token: Any) -> dict:
    '''
        RETURNS
        -------
        {
            'sub': 'alex',
            'iat': 1633226038,
            'nbf': 1633226038,
            'jti': '0d251435-c27a-4387-ad0d-ba0cb38810c8'
        }
    '''
    if not token or token == 'null':
        return {}

    try:
        return jwt.decode(token, _SECRET, algorithms=['HS256'])
    except jwt.exceptions.DecodeError:
        return {}
    except jwt.ExpiredSignatureError:
        # TO-DO: Figure out how to return custom response alerting user token is expired
        return {}