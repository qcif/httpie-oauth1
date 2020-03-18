httpie-oauth
============

Authentication plugin for `HTTPie <https://httpie.org/>`_ for OAuth 1.0a.
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

Note: RSA-SHA256 is currently under development.

Installation
------------

.. code-block:: bash

    $ pip install httpie-oauth1

Run ``http --help`` and under the "Authentication" section it should
list several OAuth 1.0a authentication mechanisms for the
``--auth-type`` option: for example, ``oauth1-hmac-sha1``,
``oauth1-rsa-sha1`` and ``oauth1-plaintext``.

Since *httpie-oauth1* depends on *httpie*, it is automatically installed if
it has not already been installed.

Dependencies
............

This plugin also install **PyJWT** and PyCA's **cryptography** packages.

On CentOS 7, it might be easier to use *yum* to install "epel-release"
and then the "python2-cryptography" packages, since *pip install*
requires a C code to be compile the cryptography package.

Alternatives
............

If only HMAC-SHA1 is required, there is an older and unmaintained
`httpie-oauth <https://github.com/httpie/httpie-oauth>`_ plugin
(note: "oauth" not "oauth1") that
might be simpler to install (since it does not require cryptographic
support for RSA public-keys).


Usage
-----

Note: In the following, the "client identifier" is what OAuth 1.0a calls the
"client key" or "consumer key". But this document calls it the "client ID" to
avoid confusing it with the RSA public or private keys. The client identifier
is a string value that identifies the client: like a username does.

HMAC-SHA1
.........

To use the HMAC-SHA1 signature method, specify "oauth1-hmac-sha1" as the
``auth-type``, and for the ``--auth`` parameter provide the client identifier,
optionally followed by a colon and the secret. If the secret is not provided,
the program will prompt for it.

.. code-block:: bash

    $ http --auth-type=oauth1-hmac-sha1 --auth=clientId:s3cr3t ...

Warning: it is not secure to enter passwords on the command line, since
command lines can be examined by other processes and saved in caches.

RSA-SHA1
........

To use the RSA-SHA1 signature method, specify "oauth1-rsa-sha1" as the
``auth-type``, and in the ``--auth`` parameter provide the client identifier,
a colon, and the name of a file containing the RSA private key.
is The file must contain a PEM formatted RSA private key.

Note: The "client identifier" is what OAuth 1.0a calls the "client key" or
"consumer key". But this document calls it the "client ID" to avoid confusing
it with the RSA public or private keys. The client identifier is a string value
that identifies the client: like a username does.

.. code-block:: bash

    $ http --auth-type=oauth1-rsa-sha1 --auth=clientId:filename ...

The filename can be a relative or absolute path to the file.

Passphrase protected private keys are not supported.

Including the client key in the private key file
++++++++++++++++++++++++++++++++++++++++++++++++

Instead of providing the client ID on the command line, it can be specified
in the preamble of the private key file.

To use this approach, only provided the private key file name to the ``--auth``
option. (That is, the argument does not contain a colon.)

The ``oauth_consumer_key`` parameter from the file is used as the client ID.

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

To use the PLAINTEXT signature method, specify "oauth1-plaintext" as the
``auth-type``, and for the ``--auth`` parameter provide the client identifier,
optionally followed by a colon and the secret. If the secret is not provided,
the program will prompt for it.

.. code-block:: bash

    $ http --auth-type=oauth1-plaintext --auth=clientId:s3cr3t ...

Warning: it is not secure to enter passwords on the command line, since
command lines can be examined by other processes and saved in caches.

Other signature methods
.......................

The other signature methods are used in the same manner, but use these values
for the ``--auth-type``:

- ``oauth-hmac-sha256``

HTTPie Sessions
...............

You can also use `HTTPie sessions <https://httpie.org/doc#sessions>`_:

.. code-block:: bash

    # Create session
    $ http --session=logged-in --auth-type=oauth1-rsa-sha1 \
           --auth='clientID:myRSAkey.pvt' https://example.org

    # Re-use auth
    $ http --session=logged-in POST https://example.org hello=world


Troubleshooting
...............

ImportError: No module named jwt.algorithms
+++++++++++++++++++++++++++++++++++++++++++

The *PyJWT* module is not available. Please install it.

AttributeError: 'module' object has no attribute 'RSAAlgorithm'
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

The PyCA's *cryptography* module is not available. Please install it.