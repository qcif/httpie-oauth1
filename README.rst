httpie-oauth
============

Authentication plugin for `HTTPie <https://httpie.org/>`_ to support OAuth 1.0a.
HTTPie is a Python command line program that makes HyperText Transfer Protocol
(HTTP) requests. It supports plugins to implement different authentication
protocols.

This plugin implements **two-legged OAuth 1.0a** with support for all the
standard *signature methods* in OAuth 1.0a:

  - HMAC-SHA1
  - RSA-SHA1
  - PLAINTEXT

It also supports several non-standard signature methods, that replaces
SHA-1 with more secure hashing algorithms:

  - HMAC-SHA256
  - HMAC-SHA512
  - RSA-SHA256
  - RSA-SHA512

Installation
------------

**Important: until this package is published on PyPI, it has to be
installed from its GitHub repository. For example, to install it with
the extras for RSA:**

.. code-block:: bash

    $ pip install 'git+https://github.com/qcif/httpie-oauth1[rsa]'


Standard install
................

A standard install has all the HMAC-based and PLAINTEXT signature methods, but
does not have any of the RSA-based signature methods.

.. code-block:: bash

    $ pip install httpie-oauth1

Since *httpie-oauth1* depends on *httpie*, *httpie* is also installed if
it has not already been installed.

With extras for RSA
...................

To include the RSA-based signature methods, install it with the "rsa" extras:

.. code-block:: bash

    $ pip install 'httpie-oauth1[rsa]'

That installs the standard install, plus the additional Python
packages needed to support the RSA cryptographic algorithms: PyCA's
*cryptography* package and the *PyJWT* package. If the RSA-based
signature methods are not needed it may be easier to use the standard
install, since there can be problems installing the cryptography
package on some systems.

Note: the quotes are necessary in some shells, because square brackets
are special characters.

Checking the install
....................

Run ``http --help`` and under the "Authentication" section it should
list the OAuth 1.0a authentication mechanisms from the plugin for the
``--auth-type`` option:

- ``oauth1-hmac-sha1``
- ``oauth-hmac-sha256``
- ``oauth-hmac-sha512``
- ``oauth1-rsa-sha1``
- ``oauth-rsa-sha256``
- ``oauth-rsa-sha512``
- ``oauth1-plaintext``


Usage
-----

Note: In the following, the "client identifier" is what OAuth 1.0a calls the
"client key" or "consumer key". But this document calls it the "client ID" to
avoid confusing it with the RSA public or private keys. The client identifier
is a string value that identifies the client: like a username does.

HMAC-SHA1
.........

To use the HMAC-SHA1 signature method, for the ``--auth-type`` argument use
``oauth1-hmac-sha1``, and for the ``--auth`` argument provide the client
identifier optionally followed by a colon and the secret. If the secret is not
provided, the program will prompt for it.

.. code-block:: bash

    $ http --auth-type=oauth1-hmac-sha1 --auth=clientId:s3cr3t ...

Warning: it is not secure to enter passwords on the command line, since
command lines can be examined by other processes and saved in caches.

RSA-SHA1
........

To use the RSA-SHA1 signature method, for the ``--auth-type`` argument use
``oauth1-rsa-sha1``, and for the ``--auth`` argument provide the client
identifier, followed by a colon, and followed by the name of a file containing
the RSA private key. The file must contain a PEM formatted RSA private key.

.. code-block:: bash

    $ http --auth-type=oauth1-rsa-sha1 --auth=clientId:filename ...

The filename can be a relative or absolute path to the file.

Passphrase protected private keys are not supported.

Including the client key in the private key file
++++++++++++++++++++++++++++++++++++++++++++++++

Instead of providing the client ID on the command line, it can be specified
in the preamble of the private key file.

To use this approach, for the ``--auth`` argument only provide the private key
file name.

The ``oauth_consumer_key`` parameter from the preamble, before the PEM encoded
private key, is used as the client ID.

For example, if the private key file contains something like this:

::

    oauth_consumer_key: myconsumerkey
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY-----

It can be used with this command:

.. code-block:: bash

    $ http --auth-type=oauth1-rsa-sha1 --auth=filename ...

PLAINTEXT
.........

To use the PLAINTEXT signature method, for the ``--auth-type`` argument
use ``oauth1-plaintext``, and for the ``--auth`` argument provide the client
identifier, optionally followed by a colon and the secret. If the secret is not
provided, the program will prompt for it.

.. code-block:: bash

    $ http --auth-type=oauth1-plaintext --auth=clientId:s3cr3t ...

Warning: it is not secure to enter passwords on the command line, since
command lines can be examined by other processes and saved in caches.

Other signature methods
.......................

The other signature methods are used in the same manner, but use these values
for the ``--auth-type``:

- ``oauth-hmac-sha256``
- ``oauth-hmac-sha512``
- ``oauth-rsa-sha256``
- ``oauth-rsa-sha512``


Troubleshooting
---------------

ModuleNotFoundError: No module named 'jwt'
..........................................

The `PyJWT <https://github.com/jpadilla/pyjwt>`_ module is not installed.

This httpie-oauth1 package depends on oauthlib, which has pyjwt (and
cryptography) as optional extra dependencies. They are optional,
because they are not needed for HMAC-based signatures. But they are
needed for RSA-based signatures. The Python installers are not very
reliable when it comes to extra dependendencies, so you may need to
manually install pyjwt if the installer did not install it.

Note: the package to install is called "pyjwt" not "jwt". They both
contain a module called "jwt".

.. code-block:: bash

    $ pip install pyjwt

ModuleNotFoundError: No module named 'jwt.algorithms'
.....................................................

The "jwt" package was installed instead of the "pyjwt" package.

Install the correct package:

.. code-block:: bash

    $ pip uninstall jwt  # optional
    $ pip install pyjwt

AttributeError: module 'jwt.algorithms' has no attribute 'RSAAlgorithm'
.......................................................................

PyCA's `cryptography <https://cryptography.io/>`_ module is not installed.

See comment in the error about a missing "jwt" module.

.. code-block:: bash

    $ pip install cryptography
