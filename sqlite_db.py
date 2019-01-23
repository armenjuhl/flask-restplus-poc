import sqlite3
from app import *

conn = sqlite3.connect('rest-plus.db')# conn = sqlite3.connect(':memory')

c = conn.cursor()

# c.execute("""CREATE TABLE user (
#             public_id int,
#             name text,
#             password text,
#             admin Boolean
#     )""")

# c.execute("""CREATE TABLE todo (
#             text text,
#             complete Boolean,
#             user_id integer
#     )""")
#
# conn.commit()

# c.execute("INSERT INTO employees VALUES ('Corey', 'Schafer', 5000)")
# print(c.execute("SELECT * FROM user"))
# print(c.execute("SELECT * FROM todo"))

# conn.close()
