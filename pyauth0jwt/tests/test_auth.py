from unittest import TestCase
from django.conf import settings

import mock
import json
import jwt
import jwcrypto.jwk as jwk, datetime

from pyauth0jwt.auth0authenticate import validate_rs256_jwt


class TestAuth(TestCase):
    jwks_response = {"keys": []}

    USER_DATA = {'username': "test@test.com", "aud": settings.AUTH0_CLIENT_ID}

    JWT = {}

    def setUp(self):
        # Create a token.
        print("Setting up.")

        jwk_key = jwk.JWK.generate(kty='RSA', size=2048)
        jwk_json = json.loads(jwk_key.export(private_key=False))
        jwk_json["use"] = "sig"
        jwk_json["kid"] = "1"

        token = jwt.encode(
            self.USER_DATA,
            jwk_key.export_to_pem(private_key=True, password=None),
            algorithm='RS256', headers={"kid": jwk_json["kid"]})

        self.JWT = token
        self.jwks_response["keys"].append(jwk_json)

    @mock.patch('pyauth0jwt.auth0authenticate.get_public_keys_from_auth0', new=mock.MagicMock(return_value=jwks_response))
    def test_verify_token(self):

        token_validation = validate_rs256_jwt(self.JWT.decode())

        assert token_validation == self.USER_DATA



