# Unit tests for the HTTPie oauth1 plugin

import os
import requests
import re
import unittest

import httpie_oauth1


# ================================================================


class TestOAuth1(unittest.TestCase):
    _username = 'client_id_in_auth_argument'

    # ----------------------------------------------------------------

    def _process(self, auth):
        # Create a prepared request

        req = requests.PreparedRequest()
        req.prepare_method('GET')
        req.prepare_url('http://example.com', {
            'a': 'b'
        })
        req.prepare_headers({'foo': 'bar'})
        req.prepare_body('', None)

        # Apply the authentication plugin to the request

        auth(req)

        # Common checks on request

        self.assertEqual(req.method, 'GET')
        self.assertEqual(req.path_url, '/?a=b')
        self.assertIsNone(req.body)
        self.assertEqual(len(req.headers), 2)

        # print('HTTP headers:')
        # for key in req.headers.keys():
        #   print(f'  {key}: {req.headers[key]}')

        # Get the authorization header value

        auth_header = req.headers['Authorization'].decode("utf-8")

        # print(auth_header)

        # Check it starts with the correct text

        _prefix = 'OAuth '

        self.assertTrue(auth_header.startswith(_prefix),
                        msg='authorization header: no OAuth: ' + auth_header)

        # Parse the rest of the text as comma separated name="value" pairs

        result = {}

        prev_name = ''

        pairs = auth_header[len(_prefix):].split(', ')
        for pair in pairs:
            matches = re.compile('^(.+)="(.+)"$').match(pair)
            self.assertIsNotNone(matches,
                                 msg='authorization header: bad: ' + pair)

            name = matches.group(1)
            value = matches.group(2)
            # print(f'  {name} = {value}')

            self.assertFalse(name in result,
                             msg='authorization header: duplicate: ' + name)
            self.assertTrue(prev_name < name,
                            msg='authorization header: bad component order: '
                                + name + ' after ' + prev_name)

            result[name] = value

        # Common checks on authorization header

        self.assertTrue('oauth_nonce' in result)
        self.assertTrue('oauth_timestamp' in result)
        self.assertEqual(result['oauth_version'], '1.0')

        # Return the name-value pairs

        return result

    # ----------------------------------------------------------------

    def test_plaintext(self):
        plugin = httpie_oauth1.OAuth1PlaintextPlugin()

        self.assertEqual(plugin.auth_type, 'oauth1-plaintext')
        self.assertTrue(plugin.auth_require)
        self.assertTrue(plugin.auth_parse)
        self.assertTrue(plugin.prompt_password)

        auth = plugin.get_auth(self._username, 'p@ssw0rd')

        oauth_auth = self._process(auth)

        self.assertEqual(oauth_auth['oauth_signature_method'], 'PLAINTEXT')
        self.assertEqual(oauth_auth['oauth_consumer_key'], self._username)

        # With PLAINTEXT, the signature is simply the secret value (encoded)
        # followed by an encoded ampersand ("%26").

        self.assertEqual(oauth_auth['oauth_signature'], 'p%2540ssw0rd%26')

    # ----------------------------------------------------------------

    def test_hmac_sha1(self):
        plugin = httpie_oauth1.OAuth1HmacSha1Plugin()

        self.assertEqual(plugin.auth_type, 'oauth1-hmac-sha1')
        self.assertTrue(plugin.auth_require)
        self.assertTrue(plugin.auth_parse)
        self.assertTrue(plugin.prompt_password)

        auth = plugin.get_auth(self._username, 'p@ssw0rd')

        oauth_auth = self._process(auth)

        self.assertEqual(oauth_auth['oauth_signature_method'], 'HMAC-SHA1')
        self.assertEqual(oauth_auth['oauth_consumer_key'], self._username)
        self.assertTrue('oauth_signature' in oauth_auth)

    # ----------------------------------------------------------------

    def test_hmac_sha256(self):
        plugin = httpie_oauth1.OAuth1HmacSha256Plugin()

        self.assertEqual(plugin.auth_type, 'oauth1-hmac-sha256')
        self.assertTrue(plugin.auth_require)
        self.assertTrue(plugin.auth_parse)
        self.assertTrue(plugin.prompt_password)

        auth = plugin.get_auth(self._username, 'p@ssw0rd')

        oauth_auth = self._process(auth)

        self.assertEqual(oauth_auth['oauth_signature_method'], 'HMAC-SHA256')
        self.assertEqual(oauth_auth['oauth_consumer_key'], self._username)
        self.assertTrue('oauth_signature' in oauth_auth)

    # ----------------------------------------------------------------

    def test_rsa_sha1(self):
        plugin = httpie_oauth1.OAuth1RsaSha1Plugin()

        self.assertEqual(plugin.auth_type, 'oauth1-rsa-sha1')
        self.assertTrue(plugin.auth_require)
        self.assertFalse(plugin.auth_parse)
        self.assertFalse(plugin.prompt_password)

        # Test RSA private key files

        test_dir = os.path.dirname(os.path.realpath(__file__))

        _rsa_key_file = test_dir + '/keys/rsa-with-consumer-key.pvt'
        _rsa_key_file_without_id = test_dir + '/keys/rsa-no-consumer-key.pvt'

        # Client ID from inside the private key file is used

        for auth_argument in [
            _rsa_key_file,
            ':' + _rsa_key_file
        ]:
            plugin.raw_auth = auth_argument
            auth = plugin.get_auth('ignored-username', 'ignored-password')
            # RSA uses the raw auth instead of username and password parameters

            oauth_auth = self._process(auth)

            self.assertEqual(oauth_auth['oauth_signature_method'], 'RSA-SHA1')
            self.assertEqual(oauth_auth['oauth_consumer_key'],
                             'client_id_in_file')
            self.assertTrue('oauth_signature' in oauth_auth)

        # Client ID in `--auth` overrides value inside private key file

        for auth_argument in [
            self._username + ':' + _rsa_key_file_without_id,
            self._username + ':' + _rsa_key_file
        ]:
            plugin.raw_auth = auth_argument
            auth = plugin.get_auth('ignored-username', 'ignored-password')
            oauth_auth = self._process(auth)
            self.assertEqual(oauth_auth['oauth_consumer_key'], self._username)


# ================================================================


if __name__ == '__main__':
    unittest.main()
