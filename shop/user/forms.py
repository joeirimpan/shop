# -*- coding: utf-8 -*-
"""User forms."""
from flask_login import current_user
from flask_wtf import Form
from shop.public.models import Country, Subdivision
from shop.user.models import User
from wtforms import PasswordField, SelectField, StringField
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

    # Override method
    def process_data(self, country):
        self.data = country.id if country else None

    # Override method
    def process_formdata(self, valuelist):
        """
        Process data received over the wire from a form.
        This will be called during form construction with data supplied
        through the `formdata` argument.
        :param valuelist: A list of strings to process.
        """
        if valuelist and isinstance(valuelist[0], basestring):
            try:
                country = Country.query.filter_by_domain([
                    ('code', '=', valuelist[0])
                ]).first()
                data = country.id
            except ValueError:
                data = None
        super(CountrySelectField, self).process_formdata([data])


class SubdivisionSelectField(SelectField):
    def __init__(self, *args, **kwargs):
        super(SubdivisionSelectField, self).__init__(*args, **kwargs)
        self.choices = []

    # Override method
    def process_data(self, subdivision):
        self.data = subdivision.id if subdivision else None

    # Override method
    def process_formdata(self, valuelist):
        """
        Process data received over the wire from a form.
        This will be called during form construction with data supplied
        through the `formdata` argument.
        :param valuelist: A list of strings to process.
        """
        if valuelist and isinstance(valuelist[0], basestring):
            # Smartystreets works for US street addresses
            country = Country.query.filter_by_domain([
                ('code', '=', 'US')
            ]).first()
            subdivision_code = 'US-%s' % valuelist[0]
            try:
                subdivision = Subdivision.query.filter_by_domain([
                    ('country', '=', country.id),
                    ('code', '=', subdivision_code)
                ]).first()
                data = subdivision.id
            except ValueError:
                data = None
        super(SubdivisionSelectField, self).process_formdata([data])

    def pre_validate(self, form):
        subdivisions = [s.id for s in Subdivision.query.filter_by(country=form.country.data).all()]
        if self.data not in subdivisions and len(subdivisions):
            raise ValidationError("Subdivision is not valid for the selected country.")


class AddressForm(Form):
    name = StringField(
        'Name',
        validators=[DataRequired()],
        render_kw={"placeholder": "e.g. John Doe"}
    )
    street = StringField(
        'Address Line 1',
        validators=[DataRequired()],
        render_kw={"placeholder": "Street address, P.O. box, company name, c/o"}
    )
    streetbis = StringField(
        'Address Line 2',
        render_kw={"placeholder": "Apartment, suite, unit, building, floor, etc."}
    )
    zip = StringField(
        'Post Code',
        validators=[DataRequired()],
        render_kw={"placeholder": "e.g. 560100"}
    )
    city = StringField(
        'City',
        validators=[DataRequired()],
        render_kw={"placeholder": "e.g. Los Angeles, Beverly Hills."}
    )
    country = CountrySelectField(
        'Country',
        validators=[DataRequired()],
        coerce=int
    )
    subdivision = SubdivisionSelectField(
        'State/Province/Region',
        validators=[DataRequired()],
        coerce=int
    )
    phone = StringField(
        'Phone',
        render_kw={"placeholder": "e.g. +1234556"}
    )


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


class AccountForm(Form):
    """Change display name form."""

    name = StringField(
        'Your Name',
        validators=[DataRequired()],
        render_kw={"placeholder": "Your Name"}
    )

    email = StringField(
        'Email',
        render_kw={"placeholder": "Email"}
    )

    phone = StringField(
        'Phone Number',
        render_kw={"placeholder": "Phone"}
    )
