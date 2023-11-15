# database.py

import MySQLdb
from config import user, db_key

db = MySQLdb.connect(host='localhost', user=user, passwd=db_key, db='powerdns_db')
cursor = db.cursor()
