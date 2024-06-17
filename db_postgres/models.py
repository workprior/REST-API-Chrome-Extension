from sqlalchemy import Column, Integer, String, BigInteger, DateTime, ForeignKey
from datetime import datetime
from db_postgres.config import db, kyiv_tz



class Person(db.Model):
    __tablename__ = 'person'
    id = Column('id', Integer, primary_key=True)
    site_id = Column('site id', BigInteger, nullable=False, unique=True)
    url = Column('url', String(128), nullable=False, unique=True)
    date_create = Column('date create', DateTime, default=lambda: datetime.now(kyiv_tz))
    description = Column('description', String(2048), nullable=True)
    user_id = Column('user id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)

    def __repr__(self):
        return f"Record('{self.site_id}', '{self.url}', '{self.date_create}')"


class Users(db.Model):
    __tablename__ = 'users'
    id = Column('id', Integer, primary_key=True)
    username = Column('username', String(64), nullable=False, unique=True)
    password = Column('password', String(64), nullable=False)

class Comment(db.Model):
    __tablename__ = 'comment'
    id = Column('id', Integer, primary_key=True)
    user_id = Column('user id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    person_id = Column('person id', Integer, ForeignKey('person.id', ondelete='CASCADE'), nullable=False)
    comment_text = Column('comment text', String(2048), nullable=False)
    date_create = Column('date create', DateTime, default=lambda: datetime.now(kyiv_tz))

