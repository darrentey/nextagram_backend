from models.base_model import BaseModel
from models.user import User
import peewee as pw
from flask_login import UserMixin


class Post(BaseModel, UserMixin):
    image = pw.CharField(unique = False)
    user = pw.ForeignKeyField(User, unique = False)