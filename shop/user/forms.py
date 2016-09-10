# -*- coding: utf-8 -*-
"""User forms."""
from flask_login import current_user
from flask_wtf import Form
from shop.public.models import Country, Subdivision
from shop.user.models import User
from wtforms import PasswordField, SelectField, StringField, TextField
from wtforms.validators import (DataRequired, Email, EqualTo, Length,
                                ValidationError)


class RegisterForm(Form):
    name = StringField(
        'Full Name',
        validators=[DataRequired()]
    )
    email = StringField(
        'Email',
        validators=[DataRequired(), Email()]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired(), Length(min=6)]
    )
    confirm = PasswordField(
        'Verify password',
        validators=[
            DataRequired(),
            EqualTo('password', message='Passwords must match')
        ]
    )

    def __init__(self, *args, **kwargs):
        """Create instance."""
        super(RegisterForm, self).__init__(*args, **kwargs)
        self.user = None

    def validate(self):
        """Validate the form."""
        initial_validation = super(RegisterForm, self).validate()

        if not initial_validation:
            return False

        if User.user_exists(self.email.data):
            self.email.errors.append('Email already registered')
            return False

        return True


class CountrySelectField(SelectField):
    def __init__(self, *args, **kwargs):
        super(CountrySelectField, self).__init__(*args, **kwargs)
        self.choices = [
            (country.id, country.name)
            for country in Country.get_list()
        ]


class SubdivisionSelectField(SelectField):
    def __init__(self, *args, **kwargs):
        super(SubdivisionSelectField, self).__init__(*args, **kwargs)
        countries = Country.get_list()
        subdivisions = Subdivision.query.filter_by(country=countries[0].id).all()
        self.choices = [
            (subdivision.id, subdivision.name) for subdivision in subdivisions
        ]


def validate_subdivision(form, field):
    """
    Enforces the subdivision actually belongs to selected country
    """
    subdivisions = [s.id for s in Subdivision.query.filter_by(country=form.country.data).all()]
    if field.data not in subdivisions and len(subdivisions):
        raise ValidationError("Subdivision is not valid for the selected country.")


class AddressForm(Form):
    name = TextField(
        'Name',
        validators=[DataRequired()],
        render_kw={"placeholder": "e.g. John Doe"}
    )
    street = TextField(
        'Address Line 1',
        validators=[DataRequired()],
        render_kw={"placeholder": "Street address, P.O. box, company name, c/o"}
    )
    streetbis = TextField(
        'Address Line 2',
        render_kw={"placeholder": "Apartment, suite, unit, building, floor, etc."}
    )
    zip = TextField(
        'Post Code',
        validators=[DataRequired()],
        render_kw={"placeholder": "e.g. 560100"}
    )
    city = TextField(
        'City',
        validators=[DataRequired()],
        render_kw={"placeholder": "e.g. Los Angeles, Beverly Hills."}
    )
    country = CountrySelectField(
        'Country',
        validators=[DataRequired()],
        coerce=int)
    subdivision = SubdivisionSelectField(
        'State/Province/Region',
        validators=[DataRequired(), validate_subdivision],
        coerce=int
    )
    phone = TextField(
        'Phone',
        render_kw={"placeholder": "e.g. +1234556"}
    )

    def __init__(self, formdata=None, obj=None, prefix='', **kwargs):
        super(AddressForm, self).__init__(formdata, obj, prefix, **kwargs)


class ChangePasswordForm(Form):
    """Change Password form."""

    old_password = PasswordField(
        'Old Password',
        validators=[DataRequired(), Length(min=6)],
        render_kw={"placeholder": "Your old password"}
    )
    new_password = PasswordField(
        'New Password',
        validators=[DataRequired(), Length(min=6)],
        render_kw={"placeholder": "Your new password"}
    )
    confirm = PasswordField(
        'Verify New Password',
        validators=[
            DataRequired(),
            EqualTo('new_password', message='Passwords must match')
        ],
        render_kw={"placeholder": "Type your new password again"}
    )

    def validate(self):
        """Validate the form."""
        initial_validation = super(ChangePasswordForm, self).validate()
        if not initial_validation:
            return False

        if not current_user.check_password(self.old_password.data):
            self.old_password.errors.append('Your old password is incorrect.')
            return False
        return True
