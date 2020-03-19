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
    python_requires='>3.6.0',
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
        'httpie>=2.0.0',
        'requests_oauthlib>=1.3.0',

        # Note: needs a version of oauthlib with HMAC-SHA512, RSA-SHA256 and
        # RSA-SHA512. These are not available in oauthlib 3.1.0.
        #
        # If they becomes available in a future public release, change the
        # following reference from the git branch to:
        #     'oauthlib[signedtoken]>=x.x.x',
        # and remove the explicit references to PyJWT and PyCA's cryptography.
        'oauthlib @ git+https://github.com/qcif/oauthlib.git@rsa-sha256',

        # The oauthlib with its "signedtoken" extras will include pyjwt and
        # cryptography. But specfifying package extras does not work when the
        # package comes from git. So this needs to explicitly include pyjwt and
        # cryptography.
        #'pyjwt>=1.7.0',
        #'cryptography>=2.5.0'
    ],

    # Instead of including PyJWT and cryptography in "install_requires" (or
    # the oauthlib[signedtoken] if it worked), putting those additional
    # packages in "extra_requires" would allow RSA support to be optional.
    # But this would makes the installation process more complicated and the
    # help/usage confusing (since there is no way to disable the RSA plugins:
    # they will be available but will always throw an exception). So for now,
    # RSA support is always installed.
    #
    # extras_require={
    #     'rsa': ['cryptography>=2.5.0', 'pyjwt>=1.7.0'],
    # },

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Programming Language :: Python',
        'Environment :: Plugins',
        'License :: OSI Approved :: BSD License',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Utilities'
    ],
)
