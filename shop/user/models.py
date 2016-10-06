# -*- coding: utf-8 -*-
"""User models."""
from flask import current_app, url_for
from flask_babel import gettext
from flask_login import UserMixin
from fulfil_client.model import BooleanType, ModelType, One2ManyType, StringType
from itsdangerous import TimestampSigner, URLSafeSerializer

from shop.extensions import fulfil
from shop.fulfilio import Model
from shop.globals import current_channel
from shop.utils import render_email


class Address(Model):
    """
    An address of a user
    """

    __model_name__ = 'party.address'

    party = ModelType('party.party')
    name = StringType(required=True)
    street = StringType()
    streetbis = StringType()
    zip = StringType()
    city = StringType()
    country = ModelType("country.country")
    subdivision = ModelType("country.subdivision")
    phone = StringType()
    full_address = StringType()


class ContactMechanism(Model):
    __model_name__ = 'party.contact_mechanism'

    party = ModelType('party.party')
    type = StringType(required=True)
    value = StringType(required=True)


class Party(Model):
    """
    A contact (party) in Fulfil.

    Needed since every user is associated with a contact
    """

    __model_name__ = 'party.party'

    name = StringType(required=True)
    contact_mechanisms = One2ManyType("party.contact_mechanism")
    addresses = One2ManyType("party.address")
    payment_profiles = One2ManyType("party.payment_profile")
    default_address = ModelType('party.address')

    def get_mechanism(self, name):
        for mechanism in self.contact_mechanisms:
            if mechanism.type == name:
                return mechanism.value
        return ''


class User(UserMixin, Model):
    """
    A user of the app.
    """

    __model_name__ = 'nereid.user'

    email = StringType(required=True)

    name = StringType(required=True)
    password = StringType()
    party = ModelType("party.party")
    active = BooleanType()

    @property
    def is_active(self):
        "For Flask login"
        return self.active

    @property
    def phone(self):
        return self.party.get_mechanism('phone')

    @property
    def default_address(self):
        return self.party.default_address

    @classmethod
    def find_user(cls, email):
        """
        Find the user from the email
        """
        return cls.query.filter_by_domain(
            [('email', 'ilike', email)]
        ).show_active_only(False).first()

    def set_password(self, password):
        """Set password."""
        self.password = password
        self.save()

    def check_password(self, value):
        """Check password."""
        return self.rpc.match_password(self.id, value)

    @classmethod
    def authenticate(cls, email, password):
        """
        Convenience method to implement
        find_user and check_password
        :param email: Email of the user
        :param password: Password
        :return: user instance if password matches
        else None
        """
        user = cls.find_user(email)
        if user and user.check_password(password):
            return user
        return None

    def save(self):
        if not self.party:
            party = Party(name=self.name)
            party.save()
            self.party = party.id
        super(User, self).save()

    @classmethod
    def user_exists(cls, email):
        """Check if the user exists"""
        return cls.query.filter_by_domain(
            [('email', 'ilike', email)]
        ).show_active_only(False).exists()

    @staticmethod
    def _signer():
        return TimestampSigner(current_app.secret_key)

    @staticmethod
    def _serializer():
        return URLSafeSerializer(current_app.secret_key)

    def _get_sign(self, salt):
        """
        Returns a timestampsigned, url_serialized sign  with a salt
        'verification'.
        """
        return self._signer().sign(self._serializer().dumps(self.id, salt=salt))

    def get_email_verification_link(self, **options):
        """
        Returns an email verification link for the user
        """
        return url_for(
            'public.verify_email',
            sign=self._get_sign('verification'),
            user_id=self.id,
            **options
        )

    def get_activation_link(self, **options):
        """
        Returns an activation link for the user
        """
        return url_for(
            'public.activate',
            sign=self._get_sign('activation'),
            user_id=self.id,
            **options
        )

    def get_reset_password_link(self, **options):
        """
        Returns a password reset link for the user
        """
        return url_for(
            'public.new_password',
            sign=self._get_sign('reset-password'),
            user_id=self.id,
            **options
        )

    def initiate_reset_password(self):
        """
        Initiate the password reset for the user
        """
        EmailQueue = fulfil.model('email.queue')

        email_message = render_email(
            current_channel.support_email,      # From
            self.email,                 # To
            gettext('Your %(channel)s password', channel=current_channel.name),  # Subj
            'emails/reset-password.text',
            'emails/reset-password.html',
            user=self,
        )
        EmailQueue.create([{
            'from_addr': current_channel.support_email,
            'to_addrs': self.email,
            'msg': email_message.as_string(),
        }])

    def get_addresses(self):
        """
        Get all addresses of the user
        """
        return Address.query.filter_by_domain(
            [('party', '=', self.party.id)]
        ).all()

    def get_magic_login_link(self, **options):
        """
        Returns a direct login link for user
        """
        return url_for(
            'public.magic_login',
            sign=self._get_sign('magic-login'),
            user_id=self.id,
            **options
        )
