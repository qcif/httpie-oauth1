httpie-oauth
============

Authentication plugin for `HTTPie <https://httpie.org/>`_ to support
OAuth 1.0a.  HTTPie is a Python command line program that makes
HyperText Transfer Protocol (HTTP) requests. Plugins allow it to use
different authentication protocols.

This plugin supports all the standard *signature methods* in OAuth
1.0a:

  - HMAC-SHA1
  - RSA-SHA1
  - PLAINTEXT

It also supports several non-standard signature methods, that replaces
SHA-1 with more secure hashing algorithms:

  - HMAC-SHA256
  - HMAC-SHA512
  - RSA-SHA256
  - RSA-SHA512

This plugin supports **two-legged OAuth 1.0a** with all the available
*signature methods*.

This plugin supports **three-legged OAuth 1.0a** with the PLAINTEXT
and HMAC-based signature methods.

Installation
------------

**Important: install this package from its GitHub repository.  It is
not yet available on PyPI.  For example, to install it with the extras
for RSA:**

.. code-block:: bash

    $ pip install 'git+https://github.com/qcif/httpie-oauth1#egg=httpie-oauth1[rsa]'

Standard install
................

A standard install has all the HMAC-based and PLAINTEXT signature methods, but
does not have any of the RSA-based signature methods.

.. code-block:: bash

    $ pip install httpie-oauth1

Since *httpie-oauth1* depends on *httpie*, *httpie* is also installed if
it has not already installed.

With extras for RSA
...................

To include the RSA-based signature methods, install it with the "rsa" extras:

.. code-block:: bash

    $ pip install 'httpie-oauth1[rsa]'

That installs the standard install, plus the Python packages needed to
support the RSA cryptographic algorithms: PyCA's *cryptography*
package and the *PyJWT* package. If the RSA-based signature methods
are not needed it may be easier to use the standard install, since
there can be problems installing the cryptography package on some
systems.

Note: the quotes are necessary in some shells, because square brackets
are special characters.

Checking the install
....................

Run ``http --help`` and under the "Authentication" section. It should
list the OAuth 1.0a authentication mechanisms for ``--auth-type``:

- ``oauth1-hmac-sha1``
- ``oauth-hmac-sha256``
- ``oauth-hmac-sha512``
- ``oauth1-rsa-sha1``
- ``oauth-rsa-sha256``
- ``oauth-rsa-sha512``
- ``oauth1-plaintext``


Usage
-----

Note: The "client identifier" is what OAuth 1.0a calls the
"client key" or "consumer key". But this document calls it the "client ID" to
avoid confusing it with the RSA public or private keys. The client identifier
is a string value that identifies the client: like a username does.

HMAC-SHA1
.........

To use the HMAC-SHA1 signature method, for the ``--auth-type``
argument use ``oauth1-hmac-sha1``.

The `--auth` can be the *client identifier*, and it will prompt for
the *client secret*.

The `--auth` can also be the *client identifier*, a colon, a less-than
sign, and the name of a file to read the *client secret* from.

.. code-block:: bash

    $ http --auth-type oauth1-hmac-sha1 --auth clientId ...

    $ http --auth-type oauth1-hmac-sha1 --auth 'clientId:<secretsFilename' ...

Note: the quotes are necessary, because the shell treats the less-than
sign as a special character.

The value can just have the *client secret* after the colon (when
there is no less-than sign). But this is not recommended, because
putting passwords on the command line is insecure.

.. code-block:: bash

    $ http --auth-type oauth1-hmac-sha1 --auth clientId:clientSecret ...

See the "Advanced auth options" section for more ways to use the auth
argument.

RSA-SHA1
........

To use the RSA-SHA1 signature method, for the ``--auth-type`` argument use
``oauth1-rsa-sha1``, and for the ``--auth`` argument provide the client
identifier, followed by a colon, and followed by the name of a file containing
the RSA private key. The file must contain a PEM formatted RSA private key.

.. code-block:: bash

    $ http --auth-type oauth1-rsa-sha1 --auth clientId:filename ...

The filename can be a relative or absolute path to the file.

Passphrase protected private keys are not supported.

Including the client key in the private key file
++++++++++++++++++++++++++++++++++++++++++++++++

Instead of providing the client ID on the command line, it can be
provided in the preamble of the private key file.

To use this approach, the ``--auth`` argument is just the private key
file name.

The ``oauth_consumer_key`` parameter from the preamble, before the PEM
encoded private key, will be the client ID.

For example, if the private key file contains something like this:

::

    oauth_consumer_key: myconsumerkey
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY-----

Use it with this command:

.. code-block:: bash

    $ http --auth-type oauth1-rsa-sha1 --auth filename ...

PLAINTEXT
.........

To use the PLAINTEXT signature method, for the ``--auth-type``
argument use ``oauth1-plaintext``

The ``--auth`` argument is the same as the HMAC--based signature
methods, and also supports the same advanced options.

.. code-block:: bash

    $ http --auth-type oauth1-plaintext --auth clientId ...

    $ http --auth-type oauth1-plaintext --auth 'clientId:<secretsFilename' ...

Other signature methods
.......................

The other signature methods are used in the same way as HMAC-SHA1 and
RSA-SHA1, but with these values for the ``--auth-type``:

- ``oauth-hmac-sha256``
- ``oauth-hmac-sha512``
- ``oauth-rsa-sha256``
- ``oauth-rsa-sha512``

Advanced auth options
.....................

The ``--auth`` argument is used for::

  * client identifier
  * client secret
  * resource owner identifier
  * resource owner secret
  * callback URI
  * parameter transmission mechanism

The argument processed as components separated by colons. It can have
between 1 to 4 components: identity, secrets, callback and type.  Components
populate the left-most value first.

The identity component contains either just the *client identifier*,
or a *client identifier* and *resource owner identifier* separated by
a semicolon. In the protocol, they appear as the
``oauth_consumer_key`` and ``oauth_token`` parameters.

The secrets component contains either just the *client secret*,
a *client secret* and *resource owner secret* separated by a semicolon,
or a less-than sign followed by the name of a file to read the secret(s)
from.

The callback URI, if it is not the empty string, appears in the
protocol in the ``oauth_callback`` parameter. The callback URI can
(and usually does) contain one or more colons: it is only the last
colon in the argument that might be the separator to the last
component.


The parameter transmission mechanism indicates how the OAuth 1.0a
parameters are transmitted. If it is not present, or the value is
"header", they are transmitted in an "Authorization" HTTP header. If
the value is "query", they are transmitted as URI query parameters. If
the value is "body", they are transmitted in the HTTP body. Any other
value is not used as a transmission mechanism: the value (including
the colon) will be a part of the callback URI.

Here are some examples.

.. code-block:: bash

    --auth clientId
    --auth 'clientId:<secretsFilename'
    --auth clientId:clientSecret
    --auth 'clientId;resourceOwnerId'
    --auth 'clientId;resourceOwnerId:clientSecret;resourceOwnerSecret'
    --auth 'clientId:<secretsFilename:https://example.com/callback'
    --auth clientId:clientSecret:https://example.com/callback
    --auth clientId:clientSecret:https://example.com/callback:header
    --auth clientId:clientSecret:https://example.com/callback:query
    --auth clientId:clientSecret:https://example.com/callback:body
    --auth clientId:clientSecret:https://example.com/callback:thisIsPartOfTheCallback
    --auth clientId::https://example.com/callback
    --auth clientId::https://example.com/callback:body
    --auth clientId:clientSecret::body
    --auth clientId:::body
    --auth 'clientId;rsrcID:cSec;rsrcSec:https://example.com/callback:body'
    --auth 'clientId;rsrcID:<secretsFilename:https://example.com/callback:body'

The first line suitable line in the secrets file will be either the
*client secret*, or the *client secret* and the *resource owner
secret* separated by a semicolon.

When searching for the first suitable line, it ignores empty or blank
lines.  Lines starting with a hash ("#"), with optional whitespace
before it, are also ignored.

.. code-block::

    # My secrets file
    # Using a secrets file is secure and convenient
        # the secrets don't appear on the command line; and
        # it doesn't have to be interactively entered.

    clientSecret;resourceOwnerSecret

Known limitations:

- *client identities*, *resource owner identities*, *client secrets*
  and *resource owner secrets* cannot contain colons or semicolons,
  and cannot start with or end with whitespace.

- *client secrets* on the command line cannot start with a less-than sign.

- the secrets file is interpreted as UTF-8.

  Troubleshooting
---------------

ModuleNotFoundError: No module named 'jwt'
..........................................

The `PyJWT <https://github.com/jpadilla/pyjwt>`_ module is not installed.

This httpie-oauth1 package depends on oauthlib, which has pyjwt (and
cryptography) as optional extra dependencies. They are optional, since
they are not needed for HMAC-based signatures. But RSA-based
signatures needs them.  Manually install the ``pyjwt`` Python package.

Note: the name of the package to install is "pyjwt", not "jwt". They
both contain a module called "jwt".

.. code-block:: bash

    $ pip install pyjwt

ModuleNotFoundError: No module named 'jwt.algorithms'
.....................................................

It is trying to use the "jwt" package, which is the wrong package.

Uninstall it and install the "pyjwt" package:

.. code-block:: bash

    $ pip uninstall jwt  # optional
    $ pip install pyjwt

AttributeError: module 'jwt.algorithms' has no attribute 'RSAAlgorithm'
.......................................................................

PyCA's `cryptography <https://cryptography.io/>`_ module is not installed.

See comment in the error about a missing "jwt" module.

.. code-block:: bash

    $ pip install cryptography
