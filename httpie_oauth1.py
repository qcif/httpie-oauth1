"""Authentication plugin for HTTPie for 2-legged OAuth 1.0a.

This plugin allows the OAuth 1.0a authentication to be used with HTTPie.
It supports all the standard signature methods defined by OAuth 1.0a:

- HMAC-SHA1
- RSA-SHA1
- PLAINTEXT

It also supports non-standard variants that replace SHA-1 more secure digest
algorithms:

- HMAC-SHA256
- HMAC-SHA512
- RSA-SHA256
- RSA-SHA512

Note: the term "client identifier or "client ID" will be used to refer to
the OAuth concepts of "client key" and "consumer key", and the HTTPie
concept of a username. It is a string that identifies the client, and is not to
be confused with an RSA public or private key.
"""

import sys
from abc import ABC
from getpass import getpass

from httpie.plugins import AuthPlugin
from requests_oauthlib import OAuth1
from oauthlib.oauth1 import (
    SIGNATURE_HMAC_SHA1,
    SIGNATURE_HMAC_SHA256,
    SIGNATURE_HMAC_SHA512,
    SIGNATURE_RSA_SHA1,
    SIGNATURE_RSA_SHA256,
    SIGNATURE_RSA_SHA512,
    SIGNATURE_PLAINTEXT
)
from oauthlib.oauth1 import (
    SIGNATURE_TYPE_AUTH_HEADER,
    SIGNATURE_TYPE_QUERY,
    SIGNATURE_TYPE_BODY
)
__version__ = '1.1.0'
__author__ = 'Hoylen Sue'
__licence__ = 'BSD'


# ################################################################

class _OAuth1RsaPluginBase(AuthPlugin, ABC):
    """
    Base class for RSA-based plugins.

    For all RSA-based signature methods, the `--auth` option is mandatory
    and must contain either:

     - the filename of a PEM formatted RSA private key; or
     - the client ID and the filename, separated by a single colon.

    When only the filename is provided, the file must contain both the PEM
    formatted private key and the client ID in the preamble before the private
    key. The client ID must be on a line with "oauth_consumer_key", followed
    by a colon, followed by the value of the client ID.
    """

    # ----------------
    # Description of --auth option used by HTTPie in its help message
    #
    # Detect if RSA support is available or not. While the plug-in cannot
    # suppress the value from appearing in the list of auth-type arguments,
    # it can change its description when RSA is not available.
    #
    # This test relies on the dependencies: httpie_oauth1 uses oauthlib, and
    # oauthlib needs PyJWT and cryptography to perform RSA signing (but those
    # two Python packages are not installed by default). Should those the
    # package dependencies change, this code will need to be updated.

    try:
        import jwt.algorithms
        _pyJwt_installed = True
    except ModuleNotFoundError:
        _pyJwt_installed = False

    try:
        import cryptography.hazmat.primitives.asymmetric.rsa
        _cryptography_installed = True
    except ModuleNotFoundError:
        _cryptography_installed = False

    description = '--auth [CLIENT_ID:]PRIVATE_KEY_FILE' \
        if _pyJwt_installed and _cryptography_installed else \
        '[not available: RSA packages not installed]'

    # ----------------

    auth_require = True   # plugin requires `--auth`

    auth_parse = False  # plugin does not want HTTPie to parse `--auth` argument

    prompt_password = False  # plugin does not prompt for a password

    # ================================================================

    def the_auth(self, signature_method: str):

        private_key, client_id = self._get_key_and_client_id()

        # Create a requests_oauthlib ``OAuth1`` with requested signature method
        # and credentials.

        return OAuth1(signature_method=signature_method,
                      client_key=client_id,
                      rsa_key=private_key)

    def _get_key_and_client_id(self):
        """
        Obtains the authentication parameters: RSA private key and client ID.

        Parse the raw_auth for an filename and optional client ID.
        The file is opened and parsed for the RSA private key (in PEM format)
        and an optional oauth_consumer_key attribute (which is used as the
        client ID if it wasn't provided in the raw_auth).

        Returns the private key and the client ID.

        If an error occurs, an error message is printed to stderr and the
        program exits.

        Note: Passpharse protected private keys are not yet supported.
        Before support for it can be implemented, the PyJWT, oauthlib and
        requests_oauthlib modules need to be updated.
        The passphrase needs to be obtained here and passed
        through to PyJWT's jwt/algorithms.py, line 168, where currently it
        passes into load_pem_private_key a hardcoded value of None for the
        password.
        To get it to there, many places in oauthlib's oauth1/rfc5849/__init__.py
        and oauth1/rfc5849/signature.py, as well as in requests_oauthlib's
        oauth1_auth.py, need to be updated to pass it through.

        :return: tuple with private key and client ID
        """

        # Since auth_parse is False, argument to `--auth` is in self.raw_auth

        parts = self.raw_auth.split(':')
        if len(parts) == 1:
            cmd_line_client_id = None
            filename = parts[0]
        elif len(parts) == 2:
            cmd_line_client_id = parts[0]
            filename = parts[1]
        else:
            sys.stderr.write(
                'http: usage error: invalid --auth argument'
                ' (expecting: [clientId:]privateKeyFile)')
            sys.exit(2)

        # Read the private key file

        if len(filename) == 0:
            sys.stderr.write('http: usage error:'
                             ' --auth missing RSA private key file')
            sys.exit(2)

        private_key, file_client_id = _OAuth1RsaPluginBase._load_file(filename)

        # Client identifier

        if cmd_line_client_id is not None and 0 < len(cmd_line_client_id):
            client_id = cmd_line_client_id  # command line value has precedence
        else:
            client_id = file_client_id

        if client_id is None or len(client_id) == 0:
            sys.stderr.write('http: usage error: on client ID in --auth'
                             ' and no oauth_consumer_key in key file')
            sys.exit(2)

        # Return result

        return private_key, client_id

    @staticmethod
    def _load_file(filename):
        """
        Loads the mandatory private key and optional consumer ID from a file.

        Prints an error message to stderr and exits if a problem occurs.

        :param filename: file to read
        :return: PEM formatted private key and client ID or None
        """

        try:
            _pem_private_key_begin = '-----BEGIN RSA PRIVATE KEY-----'
            _pem_private_key_end = '-----END RSA PRIVATE KEY-----'

            fp = open(filename)
            data = fp.read()
            fp.close()

            # Find the PEM formatted RSA private key

            key_start = data.find(_pem_private_key_begin)
            key_end = data.find(_pem_private_key_end)

            if key_start == -1:
                # Did not find the start of the PEM formatted RSA private key.
                # Identify common content for a more meaningful error message.

                if data.find('-----BEGIN PUBLIC KEY-----') != -1 or \
                        data.find('-----BEGIN RSA PUBLIC KEY-----') != -1 or \
                        data.find('ssh-rsa ') != -1 or \
                        data.find('---- BEGIN SSH2 PUBLIC KEY ----') != -1:
                    err = 'contains a public key, need a PRIVATE key'
                elif data.find('-----BEGIN OPENSSH PRIVATE KEY-----') != -1 or \
                        data.find('PuTTY-User-Key-File-2:'):
                    err = 'private key format not supported' + \
                          ', PEM format RSA private key required'
                else:
                    err = 'PEM formatted RSA private key not found'

            elif key_end == -1:
                # Found start but no end
                err = 'private key is incomplete'
            elif key_end <= key_start:
                err = 'private key file appears to be corrupted'
            else:
                key_end += len(_pem_private_key_end)  # include the end line
                err = None

            if err is not None:
                sys.stderr.write("http: error: " + err + ': ' + filename)
                sys.exit(1)

            pem_key = data[key_start:key_end]

            # Try to extract the oauth_consumer_key from the preamble

            client_id = _OAuth1RsaPluginBase._extract_attribute(
                data[0:key_start], 'oauth_consumer_key')

            # Return results

            return pem_key, client_id

        except IOError as e:
            sys.stderr.write("http: error: RSA private key file: " + str(e))
            sys.exit(1)

    @staticmethod
    def _extract_attribute(data, desired_attribute):
        """
        Extract a named parameter from the preamble text.

        Lines are recognised as parameters if they are formatted as
        "name:value". Whitespace around the name and value are ignored.
        Values can be single or double quoted. Single and double quotes inside
        quoted values can be escaped with a backslash.

        :param data: preamble text to search
        :param desired_attribute: name of attribute to extract
        :return: value, or None if not found
        """

        for line in data.splitlines():
            colon_pos = line.find(':')
            if colon_pos != -1:
                name = line[:colon_pos].strip()

                value = line[colon_pos + 1:].strip()
                if value.startswith('"') and value.endswith('"') or \
                   value.startswith("'") and value.endswith("'"):
                    value = value[1:len(value) - 1]
                    value = value.replace('\\"', '"')
                    value = value.replace("\\'", "'")

                if name == desired_attribute:
                    return value  # found

        return None  # not found


# ################################################################

class OAuth1RsaSha1Plugin(_OAuth1RsaPluginBase):
    auth_type = 'oauth1-rsa-sha1'

    name = 'OAuth 1.0a RSA-SHA1'

    def get_auth(self, username=None, password=None):
        return self.the_auth(SIGNATURE_RSA_SHA1)


# ################################################################

class OAuth1RsaSha256Plugin(_OAuth1RsaPluginBase):
    auth_type = 'oauth1-rsa-sha256'

    name = 'OAuth 1.0a RSA-SHA256'

    def get_auth(self, username=None, password=None):
        return self.the_auth(SIGNATURE_RSA_SHA256)


# ################################################################

class OAuth1RsaSha512Plugin(_OAuth1RsaPluginBase):
    auth_type = 'oauth1-rsa-sha512'

    name = 'OAuth 1.0a RSA-SHA512'

    def get_auth(self, username=None, password=None):
        return self.the_auth(SIGNATURE_RSA_SHA512)


# ################################################################

class _OAuth1SecretsBase(AuthPlugin, ABC):
    """
    Base class for HMAC-based and PLAINTEXT plugins.

    This is for signature methods that use secrets (i.e. client secrets and/or
    resource owner secrets).
    """

    description = \
        '--auth CLIENTID[;RESOURCEOWNERID][:SECRETS[:CALLBACK[:TYPE]]]'

    auth_require = True  # plugin requires `--auth`

    auth_parse = False  # plugin does not want HTTPie to parse `--auth` argument

    prompt_password = False  # plugin does not prompt for a password

    # ================================================================

    def the_auth(self, signature_method: str):
        """
        The secrets is used as the client secret, if it does not contain any
        colons. If it contains one or more colons, the substring before the
        first colon is used as the client secret and the part after the first
        colon is used as the resource owner secret (also called the "token
        shared-secret" in OAuth1 terminology). A value with no colons, or ends
        with a colon means there is no resource owner secret. A value that
        starts with a colon means there is no client secret.

        :param signature_method: the HMAC-based signature method to use
        :return:
        """

        # Since auth_parse is False, argument to `--auth` is in self.raw_auth

        # Break up into components: identities:secrets:callback:type

        _default_type = SIGNATURE_TYPE_AUTH_HEADER

        components = self.raw_auth.split(':')
        if len(components) == 1:
            # identities
            ids_component = components[0]
            secrets = None  # prompt for secrets: always
            callback = None
            sig_type = _default_type
        elif len(components) == 2:
            # identities:secrets
            ids_component = components[0]
            secrets = components[1]  # prompt for secrets: if empty string
            callback = None
            sig_type = _default_type
        else:
            # identities:secrets:callback or identities:secrets:callback:type
            # The callback can contain zero or more colons.

            ids_component = components[0]
            secrets = components[1]  # prompt for secrets: if empty string

            if len(components) == 3:
                # No transmission type component
                end_of_callback = len(components)
            else:
                # Last component is either transmission type or part of callback

                end_of_callback = len(components) - 1  # exclude last component?

                last_component = components[-1]
                if last_component == 'header':
                    sig_type = SIGNATURE_TYPE_AUTH_HEADER
                elif last_component == 'query':
                    sig_type = SIGNATURE_TYPE_QUERY
                elif last_component == 'body':
                    sig_type = SIGNATURE_TYPE_BODY
                else:
                    # Last component is not known value: it is part of callback
                    end_of_callback = len(components)  # keep last component
                    sig_type = _default_type

            callback = ':'.join(components[2:end_of_callback])

        # Split identities component into clientID;resourceOwnerID

        parts = ids_component.split(';')
        if 2 < len(parts):
            sys.stderr.write(
                'http: usage error: invalid --auth: too many semicolons'
                ' in "clientID[;resourceOwnerId]" component')
            sys.exit(2)
        client_id = parts[0].strip()
        resource_owner_id = parts[1].strip() if 1 < len(parts) else None

        # Get the secrets component, which may be embedded in the --auth
        # argument, read from a file, or prompt the user for it.

        if secrets is None or len(secrets) == 0:
            # Blank: Prompt for the secrets
            try:
                secrets = getpass(
                    'http: client secret or clientSecret;resourceOwnerSecret: ')
            except EOFError:  # if ^D entered
                sys.exit(1)
        elif secrets.startswith('<'):
            # Starts with a '<': read the secrets from a file
            secrets_filename = secrets[1:]
            try:
                secrets = None
                fp = open(secrets_filename, mode='r', encoding='UTF-8')
                for line in iter(fp.readline, ''):
                    trimmed = line.strip()
                    if len(trimmed) != 0 and not trimmed.startswith('#'):
                        secrets = trimmed
                        break
                fp.close()
                if secrets is None:
                    sys.stderr.write(
                        f'http: {secrets_filename}:'
                        f' no line with secrets found in file')
                    sys.exit(2)
            except FileNotFoundError:
                sys.stderr.write(
                    'http: secrets file not found: ' + secrets_filename)
                sys.exit(2)
        # else use the component from `--auth` as the secrets

        # Split secrets component into clientSecret;resourceOwnerSecret

        parts = secrets.split(';')
        if 2 < len(parts):
            sys.stderr.write(
                'http: usage error: too many semicolons'
                ' in "clientSecret[;resourceOwnerSecret]" component')
            sys.exit(2)
        client_secret = parts[0].strip()
        resource_owner_secret = parts[1].strip() if 1 < len(parts) else None

        # Note: they must be stripped of leading and trailing whitespace
        # for consistency. Secrets values from a file are stripped, so it would
        # be inconsistent to not do the same for secrets values from the command
        # line or the input from a prompt. Also, whitespace before or after any
        # semicolon is stripped, otherwise it would be very complicated and
        # confusing to describe all the possible situations where whitespace
        # is preserved or not.

        # Create the OAuth1 with the supplied credentials and options

        return OAuth1(signature_method=signature_method,
                      client_key=client_id,
                      client_secret=client_secret,
                      resource_owner_key=resource_owner_id,
                      resource_owner_secret=resource_owner_secret,
                      callback_uri=callback,
                      signature_type=sig_type)


# ################################################################

class OAuth1HmacSha1Plugin(_OAuth1SecretsBase):
    auth_type = 'oauth1-hmac-sha1'

    name = 'OAuth 1.0a HMAC-SHA1'

    def get_auth(self, username=None, password=None):
        return self.the_auth(SIGNATURE_HMAC_SHA1)


# ################################################################

class OAuth1HmacSha256Plugin(_OAuth1SecretsBase):
    auth_type = 'oauth1-hmac-sha256'

    name = 'OAuth 1.0a HMAC-SHA256'

    def get_auth(self, username=None, password=None):
        return self.the_auth(SIGNATURE_HMAC_SHA256)


# ################################################################

class OAuth1HmacSha512Plugin(_OAuth1SecretsBase):
    auth_type = 'oauth1-hmac-sha512'

    name = 'OAuth 1.0a HMAC-SHA512'

    def get_auth(self, username=None, password=None):
        return self.the_auth(SIGNATURE_HMAC_SHA512)


# ################################################################

class OAuth1PlaintextPlugin(_OAuth1SecretsBase):
    auth_type = 'oauth1-plaintext'

    name = 'OAuth 1.0a PLAINTEXT'

    def get_auth(self, username=None, password=None):
        return self.the_auth(SIGNATURE_PLAINTEXT)
