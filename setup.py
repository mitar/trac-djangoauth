from setuptools import setup

VERSION = '0.1.3'
PACKAGE = 'djangoauth'

setup(
    name = 'DjangoAuthPlugin',
    version = VERSION,
    description = "DjangoAuthPlugin for Trac's AccountManager authenticates against Django authentication.",
    author = 'Mitar',
    author_email = 'mitar.trac@tnode.com',
    url = 'http://mitar.tnode.com/',
    keywords = 'trac plugin',
    license = 'AGPLv3',
    packages = [PACKAGE],
    include_package_data = True,
    install_requires = [
        'TracAccountManager',
    ],
    zip_safe = False,
    entry_points = {
        'trac.plugins': '%s = %s' % (PACKAGE, PACKAGE),
    },
)
