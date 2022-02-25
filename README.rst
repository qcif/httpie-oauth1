httpie-oauth1
#############

Authentication plugin for `HTTPie <https://httpie.org/>`_ to support
**OAuth 1.0a**.  HTTPie is a Python command line program that makes
HyperText Transfer Protocol (HTTP) requests. Plugins allow it to use
different authentication protocols.

**Note:** OAuth 1.0a is very different to OAuth 2.0. This plugin
does **not** support OAuth 2.0.

This plugin supports all the standard *signature methods* in OAuth
1.0a (as defined by `RFC 5849 <https://tools.ietf.org/html/rfc5849>`_):

* HMAC-SHA1
* RSA-SHA1
* PLAINTEXT

It also supports non-standard *signature methods*, that replaces SHA-1
with more secure hashing algorithms:

* HMAC-SHA256
* HMAC-SHA512
* RSA-SHA256
* RSA-SHA512

This plugin supports **two-legged OAuth 1.0a** with all the available
*signature methods*.

This plugin can be used to support **three-legged OAuth 1.0a** with
the PLAINTEXT and HMAC-based *signature methods*, if some values are
manually copied between the different requests.

************
Installation
************

Standard install without RSA
============================

A standard install has all the HMAC-based and PLAINTEXT *signature
methods*, but does **not** have any of the RSA-based *signature methods*.

.. code-block:: bash

    $ pip install httpie-oauth1

Since *httpie-oauth1* depends on *httpie*, this also installs *httpie*
if it has not already been installed.

Run ``http --help`` and (under the "Authentication" section) the OAuth
1.0a authentication mechanisms (e.g. "oauth1-hmac-sha1") will be
available for the ``--auth-type``.


Install with extras for RSA
===========================

To include support for the RSA-based *signature methods*, install it
with the "rsa" extras:

.. code-block:: bash

    $ pip install 'httpie-oauth1[rsa]'

That installs the standard install, plus the Python packages needed to
support the RSA cryptographic algorithms: PyCA's *cryptography*
package and the *PyJWT* package. If the RSA-based *signature methods*
are not needed it may be easier to use the standard install, since
there can be problems installing the cryptography package on some
systems.

Note: the quotes are necessary in some shells, because square brackets
are special characters.

Run ``http --help`` and (under the "Authentication" section) the
RSA-based OAuth 1.0a authentication mechanisms (e.g "oauth1-rsa-sha1")
will be available for the ``--auth-type``.


*****
Usage
*****

Note: The "client identifier" is what OAuth 1.0a calls the
"client key" or "consumer key". But this document calls it the "client ID" to
avoid confusing it with the RSA public or private keys. The client identifier
is a string value that identifies the client: like a username does.

HMAC-SHA1
=========

To use the HMAC-SHA1 *signature method*, for the ``--auth-type``
argument use ``oauth1-hmac-sha1``.

The argument to ``--auth`` can be just the *client identifier*, and it
will prompt for the *client secret*.

The argument to ``--auth`` can also be the *client identifier*, a
colon, a less-than sign, and the name of a file to read the *client
secret* from.

.. code-block:: bash

    $ http --auth-type oauth1-hmac-sha1 --auth clientId ...

    $ http --auth-type oauth1-hmac-sha1 --auth 'clientId:<secretsFilename' ...

Note: the quotes are necessary, because the shell treats the less-than
sign as a special character.

The value can also just have the *client secret* after the colon (when
there is no less-than sign). But this is not recommended, because
putting passwords on the command line is insecure.

.. code-block:: bash

    $ http --auth-type oauth1-hmac-sha1 --auth clientId:clientSecret ...

See the `Advanced auth options`_ section for more ways to use the auth
argument.

RSA-SHA1
========

To use the RSA-SHA1 signature method, for the ``--auth-type`` argument use
``oauth1-rsa-sha1``, and for the ``--auth`` argument provide the client
identifier, followed by a colon, and followed by the name of a file containing
the RSA private key. The file must contain a PEM formatted RSA private key.

.. code-block:: bash

    $ http --auth-type oauth1-rsa-sha1 --auth clientId:filename ...

The filename can be a relative or absolute path to the file.

Passphrase protected private keys are not supported.

Including the client key in the private key file
------------------------------------------------

The preamble of the private key file can contain the *client
identifier*. This makes HTTPie easier to use, since the command line
only needs the filename.

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
=========

To use the PLAINTEXT signature method, for the ``--auth-type``
argument use ``oauth1-plaintext``

The ``--auth`` argument is the same as the HMAC--based signature
methods, and also supports the same `advanced auth options`_.

.. code-block:: bash

    $ http --auth-type oauth1-plaintext --auth clientId ...

    $ http --auth-type oauth1-plaintext --auth 'clientId:<secretsFilename' ...

Other signature methods
=======================

The other signature methods work in the same way as HMAC-SHA1 and
RSA-SHA1, but using these arguments for the ``--auth-type`` option:

- ``oauth-hmac-sha256`` for HMAC-SHA256
- ``oauth-hmac-sha512`` for HMAC-SHA512
- ``oauth-rsa-sha256`` for RSA-SHA256
- ``oauth-rsa-sha512`` for RSA-SHA512

Advanced auth options
=====================

The HMAC-based and PLAINTEXT signature methods supports many
properties with the ``--auth`` argument. It can specify
these values to the request:

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
protocol in the ``oauth_callback`` parameter. The callback URI
component ends at the last colon (or the end of the value), rather
than at the third colon. This allow the callback URI to contain
colons, which all URIs do.

The parameter transmission mechanism indicates where the OAuth 1.0a
parameters appear in the request:

* "query" means in the URI query parameters;
* "body" means in the HTTP body; or
* "header" means in hthe HTTP "Authorization" header.

The header is the default, if the parameter transmission mechanism is
not provided.

The header is also the default, if the value does not match any of the
known values. In this situation, the value (and the preceding colon)
will be a part of the callback URI.

Examples
--------

Examples ``--auth`` arguments:

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
    --auth clientId:clientSecret:https://example.com/callback:body:body
    --auth clientId:clientSecret:https://example.com/callback:thisIsPartOfTheCallback
    --auth clientId::https://example.com/callback
    --auth clientId::https://example.com/callback:body
    --auth clientId:clientSecret::body
    --auth clientId:::body
    --auth 'clientId;rsrcID:cSec;rsrcSec:https://example.com/callback:body'
    --auth 'clientId;rsrcID:<secretsFilename:https://example.com/callback:body'

Secrets file
------------

The first suitable line in the secrets file will be either the *client
secret*, or the *client secret* and the *resource owner secret*
separated by a semicolon.

When searching for the first suitable line, it ignores empty lines and
lines with only whitespace.  Lines starting with a hash ("#"), with
optional whitespace before it, are also ignored.

Example secrets file:

.. code-block::

    # My secrets file
    # Using a secrets file is secure and convenient
        # the secrets don't appear on the command line; and
        # it doesn't have to be interactively entered.

    clientSecret;resourceOwnerSecret

Known limitations
-----------------

- *client identities*, *resource owner identities*, *client secrets*
  and *resource owner secrets* cannot contain colons or semicolons,
  and cannot start with or end with whitespace.

- *client secrets* on the command line cannot start with a less-than sign.

- UTF-8 is the encoding for the secrets file.

*******
History
*******

This plugin is a fork of the
`httpie-oauth <https://pypi.org/project/httpie-oauth/>`_ plugin,
which is no longer being maintained.

***************
Troubleshooting
***************

ModuleNotFoundError: No module named 'jwt'
==========================================

The `PyJWT <https://github.com/jpadilla/pyjwt>`_ module is not installed.

This *httpie-oauth1* package depends on the *oauthlib* package, which
has *pyjwt* (and *cryptography*) as optional extra dependencies. They
are optional, since they are not needed for HMAC-based signatures. But
RSA-based signatures needs them.  Manually install the ``pyjwt``
Python package.

Note: the name of the package to install is "pyjwt", not "jwt". They
both contain a module called "jwt", but they are very different
implementations.

.. code-block:: bash

    $ pip install pyjwt

ModuleNotFoundError: No module named 'jwt.algorithms'
=====================================================

It is trying to use the "jwt" package, which is the wrong package.

Uninstall it and install the "pyjwt" package:

.. code-block:: bash

    $ pip uninstall jwt  # uninstall the wrong implementation of JWT
    $ pip install pyjwt  # install the correct implementation of JWT

AttributeError: module 'jwt.algorithms' has no attribute 'RSAAlgorithm'
=======================================================================

PyCA's `cryptography <https://cryptography.io/>`_ module is not installed.

See comment in the error about a missing "jwt" module.

.. code-block:: bash

    $ pip install cryptography
