from playhouse.db_url import connect
from peewee import Model
from peewee import IntegerField
from peewee import CharField
from flask_login import UserMixin


db = connect("sqlite:///peewee_db.sqlite")

if not db.connect():
    print("接続NG")
    exit()
print("接続OK")

class User(UserMixin, Model): # User というテーブルを作る
    id = IntegerField(primary_key=True) # 数字
    name = CharField() #文字
    password = CharField()  # 文字
    class Meta:
        database = db
        table_name = "user"

db.create_tables([User])       
