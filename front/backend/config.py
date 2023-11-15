# config.py

import hvac
from loguru import logger

client = hvac.Client()
client = hvac.Client(url='http://127.0.0.1:8200', token='hvs.WvGJVyK4zYPgqvZhoDSUHBIu')
secret_data = client.secrets.kv.v2.read_secret_version(path='myapp/config')

SECRET_KEY = secret_data['data']['data']['SECRET_KEY']
db_key = secret_data['data']['data']['db_key']
user = secret_data['data']['data']['user']

pdns_server = 'http://0.0.0.0:8081'
api_key = secret_data['data']['data']['api_key']

logger.debug(api_key)
