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
    version='1.1.0',
    description='OAuth 1.0a authentication plugin for HTTPie',
    author='Hoylen Sue',
    author_email='hoylen@hoylen.com',
    license='BSD',
    url='https://github.com/qcif/httpie-oauth1',
    download_url='https://github.com/qcif/httpie-oauth1',
    py_modules=['httpie_oauth1'],
    zip_safe=False,
    entry_points={
        'httpie.plugins.auth.v1': [
            'httpie_oauth1_hs1 = httpie_oauth1:OAuth1HmacSha1Plugin',
            'httpie_oauth1_rs1 = httpie_oauth1:OAuth1RsaSha1Plugin',
            'httpie_oauth1_plaintext = httpie_oauth1:OAuth1PlaintextPlugin',
            'httpie_oauth1_hs256 = httpie_oauth1:OAuth1HmacSha256Plugin',
            'httpie_oauth1_hs512 = httpie_oauth1:OAuth1HmacSha512Plugin',
            'httpie_oauth1_rs256 = httpie_oauth1:OAuth1RsaSha256Plugin',
            'httpie_oauth1_rs512 = httpie_oauth1:OAuth1RsaSha512Plugin',
        ]
    },
    install_requires=[
        'httpie>=0.7.0',
        # Note: require oauthlib with HMAC-SHA512, RSA-SHA256 and RSA-SHA512,
        # which is not available in oauthlib 3.1.0 published on PyPI.
        # If it is available in a future public release, change the following
        # reference to the git branch.
        'oauthlib @ git+https://github.com/qcif/oauthlib.git@rsa-sha256',
        'requests_oauthlib>=1.3.0',
        'pyjwt>=1.7.1',
        'cryptography>=2.8.0'
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Programming Language :: Python',
        'Environment :: Plugins',
        'License :: OSI Approved :: BSD License',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Utilities'
    ],
)
