from models.base_model import BaseModel
import peewee as pw
from flask_login import UserMixin


class User(BaseModel, UserMixin):
    username = pw.CharField(unique=True)
    email = pw.CharField(unique=True)
    password = pw.CharField(unique=False)
