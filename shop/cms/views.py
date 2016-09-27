# -*- coding: utf-8 -*-
"""CMS views."""
from flask import Blueprint, abort, redirect, url_for
from shop.cms.models import Article, ArticleCategory
from shop.utils import render_theme_template as render_template

blueprint = Blueprint(
    'pages', __name__,
    url_prefix='/pages', static_folder='../static'
)


@blueprint.route('/')
def pages_root():
    """
    Redirect page root to the home page.
    """
    return redirect(url_for('public.home'))


@blueprint.route('/<uri>')
def page(uri):
    """
    Render a page
    """
    article = Article.get_shop_query().filter_by(uri=uri).first_or_404()
    if article:
        return render_template('cms/page.html', article=article)
    return abort(404)


@blueprint.route('/category/<uri>')
def category(uri):
    """
    Render a category
    """
    category = ArticleCategory.get_shop_query().filter_by(
        unique_name=uri
    ).first_or_404()
    return render_template('cms/category.html', category=category)


@blueprint.route('/sitemap-index.xml')
def sitemap_index():
    """
    Returns a Sitemap Index Page
    """
    return __doc__


@blueprint.route('/sitemap-<int:page>.xml')
def sitemap(page):
    """
    Returns a specific page of the sitemap
    """
    return __doc__
