# setup.py
#
# To install:
#
#     pip install .
#
# To setup for development:
#
#     pip install --editable .
# ----------------------------------------------------------------

from setuptools import setup

setup(
    name='httpie-oauth1',
    version='1.2.2',
    description='OAuth 1.0a authentication plugin for HTTPie.',
    author='Hoylen Sue',
    author_email='hoylen@hoylen.com',
    license='BSD',
    url='https://github.com/qcif/httpie-oauth1',
    download_url='https://github.com/qcif/httpie-oauth1',
    py_modules=['httpie_oauth1'],
    zip_safe=False,
    python_requires='>3.6.0',

    entry_points={
        'httpie.plugins.auth.v1': [
            # If you do not want the --help text to list a signature method,
            # comment out its line below before installing.
            #
            # For example, if you do not want to install support for the
            # RSA-based signature methods, comment out all the
            # httpie_oauth1_* entries.

            'httpie_oauth1_hs1 = httpie_oauth1:OAuth1HmacSha1Plugin',
            'httpie_oauth1_hs256 = httpie_oauth1:OAuth1HmacSha256Plugin',
            'httpie_oauth1_hs512 = httpie_oauth1:OAuth1HmacSha512Plugin',

            'httpie_oauth1_rs1 = httpie_oauth1:OAuth1RsaSha1Plugin',
            'httpie_oauth1_rs256 = httpie_oauth1:OAuth1RsaSha256Plugin',
            'httpie_oauth1_rs512 = httpie_oauth1:OAuth1RsaSha512Plugin',

            'httpie_oauth1_plaintext = httpie_oauth1:OAuth1PlaintextPlugin',
        ]
    },

    install_requires=[
        'httpie>=2.0.0',
        'requests_oauthlib>=1.3.0',
        'oauthlib>=3.1.1',
    ],

    extras_require={
        # The "rsa" extras allows the RSA-based signature methods to work.
        'rsa': [
            'cryptography>=2.5.0',
            'pyjwt>=1.7.0'
        ],
    },

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Programming Language :: Python :: 3',
        'Environment :: Plugins',
        'License :: OSI Approved :: BSD License',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Utilities'
    ],
)
