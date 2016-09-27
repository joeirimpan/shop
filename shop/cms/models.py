# -*- coding: utf-8 -*-
"""CMS models."""
from flask import url_for
from fulfil_client.model import One2ManyType, StringType
from shop.fulfilio import Model, ShopQuery


class MenuItem(Model):

    __model_name__ = 'nereid.cms.menuitem'

    title = StringType()
    target = StringType()
    type_ = StringType()

    def get_tree(self, depth):
        return self.rpc.get_menu_item(self.id, depth)

    @classmethod
    def get_nav(cls, code):
        return cls.query.filter_by(code=code).first()


class BannerCategory(Model):

    __model_name__ = 'nereid.cms.banner.category'


class Banner(Model):

    __model_name__ = 'nereid.cms.banner'


class ArticleCategory(Model):

    __model_name__ = 'nereid.cms.article.category'

    title = StringType()
    unique_name = StringType()
    description = StringType()
    published_articles = One2ManyType('nereid.cms.article')

    @classmethod
    def get_shop_query(cls):
        return ShopQuery(cls.rpc, cls)

    def get_absolute_url(self):
        return url_for('pages.category', uri=self.unique_name)


class Article(Model):

    __model_name__ = 'nereid.cms.article'

    uri = StringType()
    title = StringType()
    content = StringType()

    @classmethod
    def get_shop_query(cls):
        return ShopQuery(cls.rpc, cls)

    def get_absolute_url(self):
        return url_for('pages.page', uri=self.uri)
