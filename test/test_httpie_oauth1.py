# Unit tests for the HTTPie oauth1 plugin

import os
import requests
import re
import unittest

import httpie_oauth1


# ################################################################

class TestOAuth1(unittest.TestCase):

    show_oauth_parameters = False  # set to True to print out the parameters

    _clientId = 'client_id_from_auth_argument'
    _rsrc_owner_id = 'rsrc_owner_id'

    # ================================================================

    def _apply_oauth1_plugin(self,
                             auth,
                             skip_checks=False):
        """
        Tests an OAuth 1.0a plugin.

        Create a request and apply the ``auth`` plugin to it, then check
        the "Authorization" header has the expected OAuth 1.0a parameters
        common to all OAuth 1.0a requests. Checks specific to a particular
        signature method are NOT performed.

        :param auth: HTTPie plugin
        :return: dict of parameters from the Authorization header
        """
        # Create a prepared request

        req = requests.PreparedRequest()
        req.prepare_method('POST')
        req.prepare_url('http://example.com/path', {
            'a': 'b'
        })
        req.prepare_headers({'foo': 'bar'})
        req.prepare_body('', None)

        # Apply the authentication plugin to the request

        auth(req)

        # Common checks on request

        self.assertEqual(req.method, 'POST')

        if skip_checks:
            return {}, req

        self.assertEqual(req.path_url, '/path?a=b')
        self.assertIsNone(req.body)
        # self.assertEqual(len(req.headers), 2)

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

        oauth1_params = {}

        prev_name = ''  # for checking parameters appear in alphabetical order

        pairs = auth_header[len(_prefix):].split(', ')
        for pair in pairs:
            matches = re.compile('^(.+)="(.+)"$').match(pair)
            self.assertIsNotNone(matches,
                                 msg='authorization header: bad: ' + pair)

            name = matches.group(1)
            value = matches.group(2)
            # print(f'  {name} = {value}')

            self.assertFalse(name in oauth1_params,
                             msg='authorization header: duplicate parameter: ' +
                                 name)
            self.assertTrue(prev_name < name,
                            msg='authorization header: bad parameter order: ' +
                                name + ' after ' + prev_name)

            oauth1_params[name] = value

        # Common checks on authorization header

        self.assertTrue('oauth_nonce' in oauth1_params)
        self.assertTrue('oauth_timestamp' in oauth1_params)
        self.assertEqual(oauth1_params['oauth_version'], '1.0')
        self.assertTrue('oauth_signature' in oauth1_params)

        # Return the name-value pairs

        if self.show_oauth_parameters:
            print('OAuth request parameters:\n  ' +
                  '\n  '.join(map(lambda p: f'{p}', oauth1_params.items())))

        return oauth1_params, req

    # ================================================================

    def _hmac_common(self, plugin, expected_auth_type, signature_method):
        """
        Tests a HMAC-based signature method plugin.

        :param plugin: the HMAC-based plugin
        :param expected_auth_type: value for ``--auth-type`` to use the plugin
        :param signature_method: OAuth 1.0a signature method string
        :return:
        """
        self.assertEqual(plugin.auth_type, expected_auth_type)
        self.assertTrue(plugin.auth_require)
        self.assertFalse(plugin.auth_parse)
        self.assertFalse(plugin.prompt_password)

        client_secret = 's3cr3t'
        resource_owner_secret = 'p@ssw0rd'

        for secrets_pair in [client_secret,
                             client_secret + ';',
                             client_secret + ';' + resource_owner_secret,
                             ';' + resource_owner_secret]:
            # Plugin uses the raw_auth instead of username and password
            plugin.raw_auth = self._clientId + ':' + secrets_pair
            auth = plugin.get_auth('username-ignored', 'password-ignored')

            oauth_auth, req = self._apply_oauth1_plugin(auth)

            self.assertEqual(oauth_auth['oauth_signature_method'],
                             signature_method)
            self.assertEqual(oauth_auth['oauth_consumer_key'],
                             self._clientId)

    def test_hmac_sha1(self):
        plugin = httpie_oauth1.OAuth1HmacSha1Plugin()
        self._hmac_common(plugin, 'oauth1-hmac-sha1', 'HMAC-SHA1')

    def test_hmac_sha256(self):
        plugin = httpie_oauth1.OAuth1HmacSha256Plugin()
        self._hmac_common(plugin, 'oauth1-hmac-sha256', 'HMAC-SHA256')

    def test_hmac_sha512(self):
        plugin = httpie_oauth1.OAuth1HmacSha512Plugin()
        self._hmac_common(plugin, 'oauth1-hmac-sha512', 'HMAC-SHA512')

    # ================================================================

    def _rsa_common(self, plugin, expected_auth_type, signature_method):
        """
        Tests an RSA-based signature method plugin.

        :param plugin: the RSA-based plugin
        :param expected_auth_type: value for ``--auth-type`` to use the plugin
        :param signature_method: OAuth 1.0a signature method string
        :return: None
        """

        self.assertEqual(plugin.auth_type, expected_auth_type)
        self.assertTrue(plugin.auth_require)
        self.assertFalse(plugin.auth_parse)
        self.assertFalse(plugin.prompt_password)

        # Test RSA private key files are found in the "keys" subdirectory

        test_dir = os.path.dirname(os.path.realpath(__file__))

        _rsa_key_file = test_dir + '/keys/rsa-with-consumer-key.pvt'
        _rsa_key_file_without_id = test_dir + '/keys/rsa-no-consumer-key.pvt'

        # Client ID from inside the private key file is used

        for auth_argument in [
            _rsa_key_file,
            ':' + _rsa_key_file
        ]:
            # Plugin uses the raw_auth instead of username and password
            plugin.raw_auth = auth_argument
            auth = plugin.get_auth('ignored-username', 'ignored-password')

            oauth_auth, req = self._apply_oauth1_plugin(auth)

            self.assertEqual(oauth_auth['oauth_signature_method'],
                             signature_method,
                             msg='run with --auth ' + auth_argument)
            self.assertEqual(oauth_auth['oauth_consumer_key'],
                             'client_id_in_file')

        # Client ID in `--auth` overrides any client ID inside private key file

        for auth_argument in [
            self._clientId + ':' + _rsa_key_file_without_id,
            self._clientId + ':' + _rsa_key_file
        ]:
            # Plugin uses the raw_auth instead of username and password
            plugin.raw_auth = auth_argument
            auth = plugin.get_auth('ignored-username', 'ignored-password')

            oauth_auth, req = self._apply_oauth1_plugin(auth)

            self.assertEqual(oauth_auth['oauth_signature_method'],
                             signature_method,
                             msg='run with --auth ' + auth_argument)
            self.assertEqual(oauth_auth['oauth_consumer_key'], self._clientId)

    def test_rsa_sha1(self):
        plugin = httpie_oauth1.OAuth1RsaSha1Plugin()
        self._rsa_common(plugin, 'oauth1-rsa-sha1', 'RSA-SHA1')

    def test_rsa_sha256(self):
        plugin = httpie_oauth1.OAuth1RsaSha256Plugin()
        self._rsa_common(plugin, 'oauth1-rsa-sha256', 'RSA-SHA256')

    def test_rsa_sha512(self):
        plugin = httpie_oauth1.OAuth1RsaSha512Plugin()
        self._rsa_common(plugin, 'oauth1-rsa-sha512', 'RSA-SHA512')

    # ================================================================

    def test_plaintext(self):
        plugin = httpie_oauth1.OAuth1PlaintextPlugin()

        self.assertEqual(plugin.auth_type, 'oauth1-plaintext')
        self.assertTrue(plugin.auth_require)
        self.assertFalse(plugin.auth_parse)
        self.assertFalse(plugin.prompt_password)

        client_secret = 'p@ssw0rd'
        resource_owner_secret = 's3cr3t'

        # Secrets -> oauth_signature value
        values = {
            client_secret: 'p%2540ssw0rd%26',  # "clientSecret"
            client_secret + ';': 'p%2540ssw0rd%26',  # "clientSecret;"
            client_secret + ';' + resource_owner_secret:
                'p%2540ssw0rd%26s3cr3t',  # "clientSecret;resourceOwnerSecret"
            ';' + resource_owner_secret: '%26s3cr3t'  # ";resourceOwnerSecret"
        }

        for secrets_pair in values.keys():
            # Plugin uses the raw_auth instead of username and password
            plugin.raw_auth = self._clientId + ':' + secrets_pair
            auth = plugin.get_auth('username-ignored', 'password-ignored')

            oauth_auth, req = self._apply_oauth1_plugin(auth)

            self.assertEqual(oauth_auth['oauth_signature_method'], 'PLAINTEXT')
            self.assertEqual(oauth_auth['oauth_consumer_key'], self._clientId)

            # With PLAINTEXT, the signature is just the secret value (encoded)
            # followed by an encoded ampersand ("%26") and the token key.

            expected_sig = values[secrets_pair]

            self.assertEqual(oauth_auth['oauth_signature'], expected_sig,
                             msg=f'wrong signature for {secrets_pair}')

    def test_advanced_auth_values(self):
        plugin = httpie_oauth1.OAuth1PlaintextPlugin()

        client_secret = 'p@ssw0rd'
        resource_owner_secret = 's3cr3t'

        components = ''.join([
            self._clientId,
            ';',
            self._rsrc_owner_id,
            ':',
            client_secret,
            ';',
            resource_owner_secret,
            ':',
            'https://oauth1.api.example.com:433/example/callback',
            ]
        )

        # Transmit parameters in query parameters

        plugin.raw_auth = f'{components}:query'
        auth = plugin.get_auth('username-ignored', 'password-ignored')

        _not_used, req = self._apply_oauth1_plugin(auth, skip_checks=True)

        self.assertTrue(req.path_url.startswith('/path?a=b&'))
        self._check_parameters_in_url_encoded_string(req.path_url)
        self.assertIsNone(req.body)

        # Transmit parameters in body

        plugin.raw_auth = f'{components}:body'
        auth = plugin.get_auth('username-ignored', 'password-ignored')

        _not_used, req = self._apply_oauth1_plugin(auth, skip_checks=True)

        self.assertEqual(req.path_url, '/path?a=b')
        self._check_parameters_in_url_encoded_string(req.body.decode('utf-8'))

        # Transmit parameters in header

        plugin.raw_auth = components
        auth = plugin.get_auth('username-ignored', 'password-ignored')

        params, req = self._apply_oauth1_plugin(auth, skip_checks=False)

        self._check_parameters_in_header(params, req)
        self.assertEqual(params['oauth_callback'],
                         'https%3A%2F%2Foauth1.api.example.com%3A433%2F'
                         'example%2Fcallback')

        # Transmit parameters in header ("something-else" is part of callback)

        plugin.raw_auth = f'{components}:something-else'
        auth = plugin.get_auth('username-ignored', 'password-ignored')

        params, req = self._apply_oauth1_plugin(auth, skip_checks=False)

        self._check_parameters_in_header(params, req)
        self.assertEqual(params['oauth_callback'],
                         'https%3A%2F%2Foauth1.api.example.com%3A433%2F'
                         'example%2Fcallback%3Asomething-else')

        # Transmit parameters in header (explicit transmission method specified)

        plugin.raw_auth = f'{components}:header'
        auth = plugin.get_auth('username-ignored', 'password-ignored')

        params, req = self._apply_oauth1_plugin(auth, skip_checks=False)

        self._check_parameters_in_header(params, req)
        self.assertEqual(params['oauth_callback'],
                         'https%3A%2F%2Foauth1.api.example.com%3A433%2F'
                         'example%2Fcallback')

    def _check_parameters_in_url_encoded_string(self, value: str):
        # check value of the URL (query string) or body
        self.assertTrue('&oauth_signature_method=PLAINTEXT' in value)
        self.assertTrue(f'&oauth_consumer_key={self._clientId}&' in value)
        self.assertTrue(f'&oauth_token={self._rsrc_owner_id}&' in value)
        self.assertTrue(''.join([
            '&oauth_callback=',
            'https%3A%2F%2Foauth1.api.example.com%3A433',
            '%2Fexample%2Fcallback&']) in value)
        self.assertTrue('&oauth_signature=p%2540ssw0rd%26s3cr3t' in value)

    def _check_parameters_in_header(self, params, req):
        self.assertEqual(req.path_url, '/path?a=b')
        self.assertEqual(params['oauth_signature_method'], 'PLAINTEXT')
        self.assertEqual(params['oauth_consumer_key'], self._clientId)
        self.assertEqual(params['oauth_token'], self._rsrc_owner_id)
        self.assertIsNone(req.body)




    # ################################################################

if __name__ == '__main__':
    unittest.main()
