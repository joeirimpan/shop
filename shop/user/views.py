# -*- coding: utf-8 -*-
"""User views."""
from datetime import date

from dateutil.relativedelta import relativedelta
from flask import Blueprint, abort, flash, request, url_for
from flask_login import current_user, login_required
from shop.cart.models import Sale
from shop.user.forms import AccountForm, AddressForm, ChangePasswordForm
from shop.user.models import Address, ContactMechanism
from shop.utils import render_theme_template as render_template
from werkzeug import redirect

blueprint = Blueprint(
    'user', __name__,
    url_prefix='/my', static_folder='../static'
)


@blueprint.route('/change-password', methods=["GET", "POST"])
@login_required
def change_password():
    """
    Change user's password
    """
    form = ChangePasswordForm(request.form)
    if form.validate_on_submit():
        current_user.set_password(form.new_password.data)
        flash("Your password was successfully updated!", "success")
        return redirect(url_for('public.home'))
    return render_template('users/change-password.html', form=form)


@blueprint.route('/addresses')
@login_required
def addresses():
    """List Addresses."""
    addresses = current_user.get_addresses()
    return render_template('users/addresses.html', addresses=addresses)


@blueprint.route("/addresses/new", methods=["GET", "POST"])
@login_required
def create_address():
    """
    Create an address for the current nereid_user
    GET
    ~~~
    Return an address creation form
    POST
    ~~~~
    Creates an address and redirects to the address view
    """
    address_name = "" if current_user.is_anonymous else \
        current_user.name
    form = AddressForm(request.form, name=address_name)

    if form.validate_on_submit():
        address = Address(party=current_user.party.id)
        form.populate_obj(address)
        address.save()
        flash("The new address has been added to your address book", 'success')
        return redirect(url_for('user.addresses'))

    return render_template('users/address-form.html', form=form)


@blueprint.route("/addresses/<int:address_id>/edit", methods=["GET", "POST"])
@login_required
def edit_address(address_id):
    """
    Edit an Address
    POST will update an existing address.
    GET will return a existing address edit form.
    :param address_id: ID of the address
    """
    address = Address.query.get(address_id)
    if not address.party == current_user.party:
        abort(403)

    form = AddressForm(request.form, obj=address)
    if form.validate_on_submit():
        form.populate_obj(address)
        address.save()
        flash('Your address has been updated', 'success')
        return redirect(url_for('user.addresses'))

    return render_template('users/address-edit.html', form=form, address=address)


@blueprint.route("/address/<int:address_id>/delete", methods=["POST"])
@login_required
def delete_address(address_id):
    """
    Delete an address
    POST deletes the address with the address_id
    """
    address_query = Address.query.filter_by_domain(
        [
            ('id', '=', address_id),
            ('party', '=', current_user.party.id)
        ]
    )
    if address_query.first():
        address_query.archive()
        flash("Address deleted", 'warning')
        return redirect(url_for('user.addresses'))
    else:
        abort(404)


@blueprint.route('/orders')
@login_required
def orders():
    """Render all orders
    """
    filter_by = request.args.get('filter_by', None)
    page = request.args.get('page', type=int) or None
    per_page = request.args.get('per_page', type=int) or 24

    domain = [
        ('party', '=', current_user.party.id),
    ]
    req_date = (
        date.today() + relativedelta(months=-3)
    )

    if filter_by == 'done':
        domain.append(('state', '=', 'done'))

    elif filter_by == 'canceled':
        domain.append(('state', '=', 'cancel'))

    elif filter_by == 'archived':
        # only done and cancelled orders should be in archive
        # irrespective of the date. Pre orders for example
        # could be over 3 months old and still be in the
        # processing state
        domain.append(
            ('state', 'in', ('done', 'cancel'))
        )

        # Add a sale_date domain for recent orders.
        domain.append((
            'sale_date', '<', req_date
        ))

    else:
        domain.append([
            'OR',
            ('state', 'in', ('confirmed', 'processing')),
            [
                ('state', 'in', ('done', 'cancel')),
                ('sale_date', '>=', req_date),
            ]
        ])

    # Handle order duration
    shop_query = Sale.get_shop_query().filter_by_domain(domain)
    paginate = shop_query.paginate(page=page, per_page=per_page)

    return render_template(
        'users/orders.html',
        sales=paginate.items,
        paginate=paginate
    )


@blueprint.route('/account', methods=["GET", "POST"])
@login_required
def account():
    """Render account details
    """
    form = AccountForm(
        request.form,
        name=current_user.name,
        email=current_user.email,
        phone=current_user.phone,
        default_address=current_user.default_address,
    )
    if form.validate_on_submit():
        current_user.name = form.name.data

        if form.default_address:
            party = current_user.party
            party.default_address = form.default_address.data
            party.save()

        if form.phone.data:
            # Search for existing phone
            contact_mechanism = ContactMechanism.query.filter_by_domain([
                ('party', '=', current_user.party.id),
                ('type', '=', 'phone'),
                ('value', '=', current_user.phone)
            ]).first()
            if contact_mechanism:
                contact_mechanism.value = form.phone.data
            else:
                contact_mechanism = ContactMechanism(
                    party=current_user.party.id,
                    type='phone', value=form.phone.data
                )
            contact_mechanism.save()

        current_user.save()
        return redirect(url_for('user.account'))

    return render_template('users/account.html', form=form)


@login_required
@blueprint.route('/order/<int:sale_id>')
def order(sale_id):
    """Render given sale order
    :param sale: ID of the sale Order
    """
    sale = Sale.get_by_id(sale_id)
    if sale.party.id != current_user.party.id:
        # Order does not belong to the user
        abort(403)
    return render_template('user/order.html', sale=sale)
