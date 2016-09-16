# -*- coding: utf-8 -*-
"""Product models."""
import functools

from flask import session
from flask_login import current_user
from fulfil_client.model import (Date, DecimalType, FloatType, ModelType,
                                 One2ManyType, StringType)

from shop.fulfilio import Model, ShopQuery
from shop.globals import current_channel


def require_cart_with_sale(function):
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        cart = Cart.get_active()
        if not cart.sale:
            if current_user.is_anonymous:
                party = current_channel.anonymous_customer
            else:
                party = current_user.party
            sale_data = {
                "party": party.id,
                "invoice_address": None,
                "shipment_address": None,
                "company": current_channel.company,
                "currency": current_channel.currency,
                "is_cart": True,
                "channel": current_channel.id,
            }
            sale_data.update(Sale.rpc.on_change_channel(sale_data))
            sale = Sale(**{
                k: v for k, v in sale_data.iteritems()
                if '.' not in k
            }).save()
            cart.sale = sale.id
            cart.save()
        return function(*args, **kwargs)
    return wrapper


class SaleLine(Model):
    __model_name__ = 'sale.line'

    product = ModelType("product.product")
    quantity = FloatType()
    unit_price = DecimalType()
    amount = DecimalType()
    description = StringType()


class Sale(Model):
    __model_name__ = 'sale.sale'

    number = StringType()
    party = ModelType("party.party")
    shipment_address = ModelType("party.address")
    invoice_address = ModelType("party.address")
    total_amount = DecimalType()
    tax_amount = DecimalType()
    untaxed_amount = DecimalType()
    lines = One2ManyType("sale.line")
    invoices = One2ManyType("account.invoice")
    sale_date = Date()
    state = StringType()
    currency = StringType()

    #: This access code will be cross checked if the user is guest for a match
    #: to optionally display the order to an user who has not authenticated
    #: as yet
    guest_access_code = StringType()

    @classmethod
    def get_shop_query(cls):
        return ShopQuery(cls.rpc, cls)

    def add_product(self, product_id, quantity):
        # check if SaleLine already exists
        sale_line = SaleLine.query.filter_by_domain([
            ('product', '=', product_id),
            ('sale', '=', self.id),
        ]).first()
        if sale_line:
            sale_line.quantity = quantity
            sale_line.save()
        else:
            line_data = {
                'sale': self.id,
                'product': product_id,
                'quantity': quantity,
                '_parent_sale.shipment_address': self.shipment_address and
                self.shipment_address.id,
                '_parent_sale.channel': current_channel.id,
                '_parent_sale.party': current_channel.anonymous_customer.id,
                '_parent_sale.currency': current_channel.currency,
                'warehouse': current_channel.warehouse
            }
            line_data.update(SaleLine.rpc.on_change_product(line_data))
            SaleLine(**{
                k: v for k, v in line_data.iteritems()
                if '.' not in k
            }).save()


class Cart(Model):
    __model_name__ = 'nereid.cart'

    sessionid = StringType()
    sale = ModelType("sale.sale")

    def confirm(self):
        "Move order to confirmation state"
        sale = self.sale
        Sale.rpc.quote([sale.id])
        Sale.rpc.confirm([sale.id])

        # TODO: Set sale_date to today
        self.sale = None
        self.save()

    @property
    def size(self):
        # TODO: Assuming every item has same unit
        if self.is_empty:
            return 0
        return sum(map(lambda l: l.quantity, self.lines))

    @property
    def is_empty(self):
        if not self.sale:
            return True
        if len(self.sale.lines) == 0:
            return True
        return False

    @classmethod
    def get_active(cls):
        """Always return a cart
        TODO: Make it work for logged in user
        """
        cart = Cart.query.filter_by_domain(
            [
                ['sessionid', '=', session.sid],
            ]
        ).first()
        if not cart:
            cart = Cart(sessionid=session.sid).save()
        return cart

    @require_cart_with_sale
    def add_product(self, product_id, quantity):
        self.refresh()
        self.sale.add_product(product_id, quantity)

    def remove_sale_line(self, line_id):
        self.refresh()
        SaleLine.rpc.delete([line_id])

    def clear(self):
        self.sale = None
        self.save()
