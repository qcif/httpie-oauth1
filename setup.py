# setup.py
#
# Example usage:
#
#     pip install .
#
#     python3 setup.py develop
#     pip install --editable .

from setuptools import setup

setup(
    name='httpie-oauth1',
    version='1.0.0',
    description='OAuth 1.0a authentication plugin for HTTPie',
    author='Hoylen Sue',
    author_email='hoylen@hoylen.com',
    license='BSD',
    url='https://github.com/hoylen/httpie-oauth1',
    download_url='https://github.com/hoylen/httpie-oauth1',
    py_modules=['httpie_oauth1'],
    zip_safe=False,
    entry_points={
        'httpie.plugins.auth.v1': [
            'httpie_oauth1_hs1 = httpie_oauth1:OAuth1HmacSha1Plugin',
            'httpie_oauth1_rs1 = httpie_oauth1:OAuth1RsaSha1Plugin',
            'httpie_oauth1_plaintext = httpie_oauth1:OAuth1PlaintextPlugin',
            'httpie_oauth1_hs256 = httpie_oauth1:OAuth1HmacSha256Plugin',
            # 'httpie_oauth1_rs256 = httpie_oauth1:OAuth1RsaSha256Plugin',
            # 'httpie_oauth1_rs512 = httpie_oauth1:OAuth1RsaSha512Plugin',
        ]
    },
    install_requires=[
        'httpie>=0.7.0',
        'requests-oauthlib>=0.3.2',
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
