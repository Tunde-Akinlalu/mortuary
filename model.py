from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from sqlalchemy import ForeignKey
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_manager

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mortuary.db'
app.config['SECRET_KEY'] = 'MortuaryKey'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# initialize the database
db = SQLAlchemy(app)


class Roles(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String, nullable=False)
    staff_list = db.relationship('Staff_list', backref='roles')

    def __repr__(self):
        return '<Name %r>' % self.id

   # def __repr__(self):
    #    return self.id


def role_choice():
       return Roles.query


class Staff_list(UserMixin, db.Model):
    __tablename__ = 'staff_list'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(20), nullable=False)
    phone_no = db.Column(db.Integer(), nullable=False)
    password = db.Column(db.String(20), nullable=False)
    role_id = db.Column(db.Integer, ForeignKey('roles.id'))
    date_joined = db.Column(db.DateTime(), default=datetime.utcnow, index=True)
    deceased = db.relationship('Deceased', backref='staff_list')
    #staff_list = db.relationship("Roles")

    def set_password(self, password):
        self.password = generate_password_hash(password, method='sha256')


    def check_password(self, password):
        return check_password_hash(self.password, password)


    def __repr__(self):
        return '<Name %r>' % self.id

def staff_choice():
    return Staff_list.query


class Wards(db.Model):
    __tablename__ = 'wards'
    id = db.Column(db.Integer, primary_key=True)
    ward_name = db.Column(db.String, nullable=False)
    deceased = db.relationship('Deceased', backref='wards')


    def __repr__(self):
        return '<Name %r>' % self.id


def ward_choices():
    return Wards.query


class Depositor(db.Model):
    __tablename__ = 'depositor'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(20), nullable=False)
    last_name = db.Column(db.String(20), nullable=False)
    phone_no = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String(120), nullable=True)
    address = db.Column(db.String(200), nullable=False)
    deceased = db.relationship('Deceased', backref='depositor')

    def __repr__(self):
        return '<Name %r>' % (self.id)

def depositor_choice():
    return Depositor.query



class Storage(db.Model):
    __tablename__ = 'storage'
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(20), nullable=False)
    type = db.Column(db.String(20), nullable=False)
    deceased = db.relationship('Deceased', backref='storage')

    def __repr__(self):
        return '<Name %r>' % (self.id)


def storage_choice():
    return Storage.query


class Deceased(db.Model):
    __tablename__ = 'deceased'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(20), nullable=False)
    last_name = db.Column(db.String(20), nullable=False)
    gender = db.Column(db.String(20), nullable=False)
    received_by = db.Column(db.Integer, ForeignKey('staff_list.id'))   # Must be small letters referencing tablename
    deposited_by = db.Column(db.Integer, ForeignKey('depositor.id'))
    deposited_in = db.Column(db.Integer, ForeignKey('storage.id'))
    # documented_by = db.Column(db.Integer, ForeignKey('staff_list.id'))
    ward = db.Column(db.Integer, ForeignKey('wards.id'))
    date_deposited = db.Column(db.DateTime(), default=datetime.utcnow)
    date_discharged = db.Column(db.DateTime)


    def __repr__(self):
        return '<Name %r>' % (self.first_name)
