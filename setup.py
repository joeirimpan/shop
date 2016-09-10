from setuptools import find_packages, setup

setup(
    name='Fulfil-Shop',
    version='0.1dev3',
    packages=find_packages(),
    license='BSD',
    include_package_data=True,
    zip_safe=False,
    long_description=open('README.rst').read(),
    install_requires=[
        'Flask',
        'Flask-WTF',
        'Flask-Assets',
        'cssmin',
        'jsmin',
        'Flask-Login',
        'Flask-Cache',
        'Flask-DebugToolbar',
        'Flask-Themes2',
        'Flask-Babel',
        'Flask-Redis',
        'Flask-Session',
        'Flask-Fulfil',
        'raven[flask]',
        'premailer',
    ]
)
