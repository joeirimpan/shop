from flask.globals import LocalProxy, _find_app, current_app


def _find_cache():
    """
    The application context will be automatically handled by
    _find_app method in flask
    """
    app = _find_app()
    return app.cache


def _get_current_channel():
    from shop.public.models import Channel
    return Channel.from_cache(
        int(current_app.config['FULFIL_CHANNEL'])
    )


def _get_current_cart():
    from shop.cart.models import Cart
    return Cart.get_active()


def _get_current_context():
    from shop.extensions import fulfil
    return fulfil.client.context


cache = LocalProxy(_find_cache)
current_channel = LocalProxy(lambda: _get_current_channel())
current_cart = LocalProxy(lambda: _get_current_cart())
current_context = LocalProxy(lambda: _get_current_context())
