import sqlite3

import login as login
from flask import Flask, render_template, flash, redirect, request, url_for, Response, make_response
from flask_wtf import FlaskForm
from sqlalchemy.orm import backref, relationship
from sqlalchemy.exc import IntegrityError, InterfaceError, InternalError
from wtforms import StringField, IntegerField, SelectField, SubmitField, TextAreaField, \
    EmailField, PasswordField, BooleanField, DateTimeField
from wtforms.validators import InputRequired, Email, EqualTo, DataRequired, Length
from wtforms import ValidationError
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import mimerender
import pdfkit
from sqlalchemy import Column, ForeignKey, String, Table
import os
import csv
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_manager, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_required
from wtforms_sqlalchemy.fields import QuerySelectField
from flask_migrate import Migrate
from sqlalchemy.engine import Engine
from sqlalchemy import event, create_engine
from jinja2 import environment
from io import StringIO

from model import app, db, Storage, Staff_list, Wards, Deceased, Depositor, Roles
from model import ward_choices, role_choice, staff_choice, storage_choice, depositor_choice

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(id):
    return Staff_list.query.filter(Staff_list.id == int(id)).first()


class StaffForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    phone_no = IntegerField('Phone Number', validators=[DataRequired()])
    password1 = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Confirm Password', validators=[DataRequired(),
                                                              EqualTo('password1', message="Passwords must match!"),
                                                              ])
    role_id = QuerySelectField(query_factory=role_choice, allow_blank=True, get_label='role_name',
                               blank_text="--Choose a role--", validators=[DataRequired()])
    submit = SubmitField('Register')


def validate_email(self, email):
    if Staff_list.query.filter_by(email=email.data).first():
        raise ValidationError("Email already registered!")


def validate_username(self, username):
    if Staff_list.query.filter_by(username=username.data).first():
        raise ValidationError("Username already taken!")


# @app.route("/forbidden",methods=['GET', 'POST'])
# @login_required
# def protected():
#   return redirect(url_for('login'))

@login_manager.unauthorized_handler
def unauthorized_callback():
    flash(f"login required", "warning")
    return redirect(url_for('login'))


@app.route("/", methods=("GET", "POST"))
def index():
    return render_template("index.html")


@app.route('/register/', methods=['POST', 'GET'])
def register():
    form = StaffForm()
    username = form.username
    if form.validate_on_submit():
        try:
            staff = Staff_list(username=form.username.data, email=form.email.data, phone_no=form.phone_no.data,
                               role_id=form.role_id.data.id)
            staff.set_password(form.password1.data)
            db.session.add(staff)
            db.session.commit()
            flash("User added successfully. Now you can log in", "success")
            return redirect(url_for('login'))
        except IntegrityError:
            flash('Input error! Check your input', 'danger')
            return redirect(url_for('register'))


        except InterfaceError:
            flash('Something is broken, contact admin', 'danger')
            return redirect(url_for('register'))

        except InternalError:
            flash('Internal error, contact Admin. Thank you', 'danger')
            redirect(url_for('register'))
    return render_template('register.html', form=form)


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


@app.route('/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Staff_list.query.filter_by(email=form.email.data).first()
        if user is not None and user.check_password(form.password.data):
            login_user(user)
            next = request.args.get("next")
            flash(f"Login Successfull!!!!.", "success")
            return redirect(url_for('depositor_rec'))
    # else:
    # flash("You need to register", "warning")
    # return redirect(url_for('register'))
    return render_template('login.html', form=form)


@app.route("/logout/")
def logout():
    logout_user()
    flash("You have been logged out", "success")
    return redirect(url_for('login'))


class DepositorForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    phone_no = IntegerField('Phone Number', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    address = TextAreaField('Address', validators=[DataRequired()])
    submit = SubmitField('Next')


@app.route('/depositor_rec/', methods=['GET', 'POST'])
# @login_required
def depositor_rec():
    form = DepositorForm()
    if form.validate_on_submit():
        new_depositor = Depositor(first_name=form.first_name.data.upper(),
                                  last_name=form.last_name.data.upper(),
                                  phone_no=form.phone_no.data,
                                  email=form.email.data.upper(),
                                  address=form.address.data.upper()
                                  )

        db.session.add(new_depositor)
        db.session.commit()
        flash("Record added successfully", "success")
        return redirect(url_for('deceased_rec'))
        # flash('Something broke! Check your input', 'danger')
    return render_template('depositor_rec.html', form=form)


class DeceasedForm(FlaskForm):
    first_name = StringField('First Name of the Deceased', validators=[DataRequired()])
    last_name = StringField('Last Name of the Deceased', validators=[DataRequired()])
    gender = SelectField("Gender", choices=[('', ''), ('Male', 'male'), ('Female', 'female')],
                         validators=[InputRequired()])
    received_by = QuerySelectField(query_factory=staff_choice, allow_blank=True, get_label='username',
                                   blank_text="--Choose a staff--", validators=[DataRequired()])
    deposited_by = QuerySelectField(query_factory=depositor_choice, allow_blank=True,
                                    get_label="last_name",
                                    blank_text="--Brought in by--", validators=[DataRequired()])
    deposited_in = QuerySelectField(query_factory=storage_choice, allow_blank=True, get_label='description',
                                    blank_text="--storage--", validators=[DataRequired()])
    ward = QuerySelectField(query_factory=ward_choices, allow_blank=True, get_label='ward_name',
                            blank_text="--Place of death--", validators=[DataRequired()])
    date_discharged = DateTimeField("Date Released", format='%Y-%m-%d')
    submit = SubmitField('Submit')


@app.route('/deceased_rec/', methods=['POST', 'GET'])
def deceased_rec():
    form = DeceasedForm()
    if form.validate_on_submit():
        deceased = Deceased(first_name=form.first_name.data, last_name=form.last_name.data,
                            gender=form.gender.data,
                            received_by=form.received_by.data.id, deposited_by=form.deposited_by.data.id,
                            deposited_in=form.deposited_in.data.id, ward=form.ward.data.id,
                            date_discharged=form.date_discharged.data)
        db.session.add(deceased)
        db.session.commit()
        flash("Added successfully.", "success")
        return redirect(url_for('index'))
    return render_template('deceased_rec.html', form=form)



@app.route('/<int:deceased_id>/discharge/', methods=('GET', 'POST'))
def discharge(deceased_id):
    form = DeceasedForm()
    deceased = Deceased.query.order_by(Deceased.id.asc()).get_or_404(deceased_id)
    if request.method == 'POST':
        deceased.first_name = request.form['first_name']
        deceased.last_name = request.form['last_name']
        deceased.gender = request.form['gender']
        deceased.received_by = request.form['received_by']
        deceased.deposited_by = request.form['deposited_by']
        deceased.deposited_in = request.form['deposited_in']
        deceased.ward = request.form['ward']
        deceased.date_discharged = request.form['date_discharged']

        db.session.commit()

        return redirect(url_for('deceased', deceased_id=deceased.id))
    return render_template('discharge.html', form=form, deceased=deceased)




pages = 10

@app.route('/search', methods=['GET', 'POST'], defaults={"page": 1})
@app.route('/search/<int:page>', methods=['GET', 'POST'])
def search(page):
    page = request.args.get('page', 1, type=int)
    tday = datetime.utcnow()
    deceased = Deceased.query.order_by(Deceased.id.asc()).paginate(page=page, per_page=pages)
    if request.method == 'POST' and 'tag' in request.form:
        tag = request.form["tag"]
        search = "%{}%".format(tag)
        deceased = Deceased.query.filter(Deceased.first_name.like(search)).paginate(per_page=pages,
                                                                                    error_out=True)
        return render_template('search.html', deceased=deceased, tag=tag)
    return render_template('search.html', deceased=deceased)


@app.route('/<int:deceased_id>/')
def deceased(deceased_id):
    deceased = Deceased.query.order_by(Deceased.id.asc()).get_or_404(deceased_id)
    return render_template('deceased.html', deceased=deceased)


@app.route('/<int:deceased_id>/edit/', methods=('GET', 'POST'))
def edit(deceased_id):
    form = DeceasedForm()
    deceased = Deceased.query.order_by(Deceased.id.asc()).get_or_404(deceased_id)
    if request.method == 'POST':
        deceased.first_name = request.form['first_name']
        deceased.last_name = request.form['last_name']
        deceased.gender = request.form['gender']
        deceased.received_by = request.form['received_by']
        deceased.deposited_by = request.form['deposited_by']
        deceased.deposited_in = request.form['deposited_in']
        deceased.ward = request.form['ward']

        db.session.commit()

        return redirect(url_for('deceased', deceased_id=deceased.id))
    return render_template('edit.html', form=form, deceased=deceased)


@app.route('/<int:deceased_id>/delete/')
def delete(deceased_id):
    deceased = Deceased.query.order_by(Deceased.id.asc()).get_or_404(deceased_id)
    db.session.delete(deceased)
    db.session.commit()
    flash("Record deleted successfully", "danger")
    return redirect(url_for('search'))






# Download Deceased invoice

# @app.route('/download/')
# def download():
#    deceased_id = ""
#    html = render_template("deceased.html", deceased_id=deceased.id)
#    pdf = pdfkit.from_string(html, False)
#    response = make_response(pdf)
#    response.headers["Content-Type"] = "application/pdf"
#    response.headers["Content-Disposition"] = "inline; filename=output.pdf"
#    return response






if __name__ == '__main__':
    app.run(debug=True)

# to delete a single table
# table_name.__table__.drop(db.engine)

# to create a single table in addition
# db.create_all()
