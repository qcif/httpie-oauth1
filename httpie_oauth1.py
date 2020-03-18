"""Plugin for HTTPie for 2-legged OAuth 1.0a with RSA-SHA1 authentication.

This plugin allows the "RSA-SHA1" signature method to be used with HTTPie.

The authentication parameter is treated as a list of colon separated fields.

The first field is the client identifier, and is used as the
oauth_client_key parameter.

The second parameter is the name of a file containing the RSA private
key. The file must contain a PEM formatted RSA private key.  The
filename can have an absolute or relative path. Password protected private
keys are not supported.

If the file name is omitted, the program will prompt for it.

If the client identifier is an empty string, the program attempts
to look for an "oauth_client_key" parameter from the beginning of the
private key file.

Note: the term "client identifier or "client ID" will be used to refer to
the OAuth concepts of "client key" and "consumer key", and the HTTPie
concept of a username. It is a string that identifies the client, and must
not be confused with an RSA public or private key.
"""

import sys
from abc import ABC

from httpie.plugins import AuthPlugin
from requests_oauthlib import OAuth1
from oauthlib.oauth1 import \
    SIGNATURE_HMAC_SHA1, \
    SIGNATURE_RSA, \
    SIGNATURE_PLAINTEXT, \
    SIGNATURE_HMAC_SHA256

__version__ = '1.0.0'
__author__ = 'Hoylen Sue'
__licence__ = 'BSD'

# ================================================================


class _OAuth1RsaPluginBase(AuthPlugin, ABC):

    description = '--auth [clientId:]privateKeyFile'

    # This plugin requires credentials to be specified with `--auth`
    auth_require = True

    # This plugin does not want the argument to `--auth` to be parsed by HTTPie
    auth_parse = False

    # This plugin does not prompt for a password
    prompt_password = False

    # ----------------------------------------------------------------

    def get_key_and_client_id(self):
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

    # ----------------

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

    # ----------------

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


# ================================================================


class OAuth1RsaSha1Plugin(_OAuth1RsaPluginBase):

    # This plugin is activated if this value is the argument to `--auth-type`
    auth_type = 'oauth1-rsa-sha1'

    name = 'OAuth 1.0a RSA-SHA1'

    # ----------------------------------------------------------------

    def get_auth(self, username=None, password=None):
        """
        Generate OAuth 1.0a 2-legged RSA-SHA1 authentication for HTTPie.

        Note: Passpharse protected private keys are not yet supported.

        :param username: ignored since auth_parse is False
        :param password: ignored since auth_parse is False
        :return: requests_oauthlib.oauth1_auth.OAuth1 object
        """

        private_key, client_id = self.get_key_and_client_id()

        return OAuth1(client_key=client_id,
                      signature_method=SIGNATURE_RSA,
                      rsa_key=private_key)


# ================================================================


# class OAuth1RsaSha256Plugin(_OAuth1RsaPluginBase):
#
#     # This plugin is activated if this value is the argument to `--auth-type`
#     auth_type = 'oauth1-rsa-sha256'
#
#     name = 'OAuth 1.0a RSA-SHA256'
#
#     # ----------------------------------------------------------------
#
#     def get_auth(self, username=None, password=None):
#         """
#         Generate OAuth 1.0a 2-legged RSA-SHA256 authentication for HTTPie.
#
#         This is a non-standard signature method, but is more stronger
#         than the standard RSA-SHA1 signature method.
#
#         :param username: ignored since auth_parse is False
#         :param password: ignored since auth_parse is False
#         :return: requests_oauthlib.oauth1_auth.OAuth1 object
#         """
#
#         private_key, client_id = self.get_key_and_client_id()
#
#         return OAuth1(client_key=client_id,
#                       signature_method=SIGNATURE_RSA_SHA256,
#                       rsa_key=private_key)


# ================================================================


# class OAuth1RsaSha512Plugin(_OAuth1RsaPluginBase):
#
#     # This plugin is activated if this value is the argument to `--auth-type`
#     auth_type = 'oauth1-rsa-sha512'
#
#     name = 'OAuth 1.0a RSA-SHA512'
#
#     # ----------------------------------------------------------------
#
#     def get_auth(self, username=None, password=None):
#         """
#         Generate OAuth 1.0a 2-legged RSA-SHA512 authentication for HTTPie.
#
#         This is a non-standard signature method, but is more stronger
#         than the standard RSA-SHA1 signature method.
#
#         :param username: ignored since auth_parse is False
#         :param password: ignored since auth_parse is False
#         :return: requests_oauthlib.oauth1_auth.OAuth1 object
#         """
#
#         private_key, client_id = self.get_key_and_client_id()
#
#         return OAuth1(client_key=client_id,
#                       signature_method=SIGNATURE_RSA_SHA512,
#                       rsa_key=private_key)


# ================================================================


class OAuth1HmacSha1Plugin(AuthPlugin):

    # This plugin is activated if this value is the argument to `--auth-type`
    auth_type = 'oauth1-hmac-sha1'

    name = 'OAuth 1.0a HMAC-SHA1'

    description = '--auth clientId:clientSecret'

    # This plugin requires credentials to be specified with `--auth`
    auth_require = True

    # This plugin wants the argument to `--auth` to be parsed by HTTPie
    auth_parse = True

    # This plugin can prompt for a password
    prompt_password = True

    # ----------------------------------------------------------------

    def get_auth(self, username=None, password=None):
        """
        Generate OAuth 1.0a 2-legged HMAC-SHA1 authentication for HTTPie.

        :param username: client key
        :param password: client secret
        :return: requests_oauthlib.oauth1_auth.OAuth1 object
        """

        return OAuth1(client_key=username,
                      signature_method=SIGNATURE_HMAC_SHA1,
                      client_secret=password)

# ================================================================


class OAuth1HmacSha256Plugin(AuthPlugin):

    # This plugin is activated if this value is the argument to `--auth-type`
    auth_type = 'oauth1-hmac-sha256'

    name = 'OAuth 1.0a HMAC-SHA256'

    description = '--auth clientId:clientSecret'

    # This plugin requires credentials to be specified with `--auth`
    auth_require = True

    # This plugin wants the argument to `--auth` to be parsed by HTTPie
    auth_parse = True

    # This plugin can prompt for a password
    prompt_password = True

    # ----------------------------------------------------------------

    def get_auth(self, username=None, password=None):
        """
        Generate OAuth 1.0a 2-legged HMAC-SHA256 authentication for HTTPie.

        :param username: client key
        :param password: client secret
        :return: requests_oauthlib.oauth1_auth.OAuth1 object
        """

        return OAuth1(client_key=username,
                      signature_method=SIGNATURE_HMAC_SHA256,
                      client_secret=password)

# ================================================================


class OAuth1PlaintextPlugin(AuthPlugin):

    # This plugin is activated if this value is the argument to `--auth-type`
    auth_type = 'oauth1-plaintext'

    name = 'OAuth 1.0a PLAINTEXT'

    description = '--auth clientId:clientSecret'

    # This plugin requires credentials to be specified with `--auth`
    auth_require = True

    # This plugin wants the argument to `--auth` to be parsed by HTTPie
    auth_parse = True

    # This plugin can prompt for a password
    prompt_password = True

    # ----------------------------------------------------------------

    def get_auth(self, username=None, password=None):
        """
        Generate OAuth 1.0a 2-legged PLAINTEXT authentication for HTTPie.

        :param username: client key
        :param password: client secret
        :return: requests_oauthlib.oauth1_auth.OAuth1 object
        """

        return OAuth1(client_key=username,
                      signature_method=SIGNATURE_PLAINTEXT,
                      client_secret=password)