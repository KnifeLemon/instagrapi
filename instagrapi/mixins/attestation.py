import base64
import time
from typing import Any, Dict, Optional
from uuid import uuid4

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Random import get_random_bytes
from Cryptodome.Signature import DSS

from instagrapi.utils.serialization import dumps

# client_doc_id of IGUSDIDRegistrationMutation in Instagram 441.0.0.0.72
USDID_REGISTRATION_CLIENT_DOC_ID = "12493035195717459304122022535"
# The app signs a device token valid for one hour and re-signs it afterwards
USDID_TOKEN_TTL = 3600
# Re-sign this many seconds before the current token expires
USDID_REFRESH_MARGIN = 300
# Error the app reports when it cannot sign the keystore challenge nonce.
# Instagram accepts the login even when attestation is in this error state.
ATTESTATION_KEYSTORE_ERROR = -1013


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class DeviceAttestationMixin:
    """
    Device signals the current Android app sends alongside CAA login.

    ``X-Meta-Usdid`` is an ordinary EC P-256 signature produced by a key the app
    generates itself, so it can be reproduced here. The keystore attestation
    (``X-Ig-Attest-Params``) needs a hardware-backed key that cannot be
    reproduced, but Instagram accepts the request while attestation reports the
    error state, so only the server-issued ``challenge_nonce`` is required.
    """

    usdid = ""
    usdid_kid = ""
    usdid_private_key = ""
    usdid_registered = False
    attestation_challenge_nonce = ""
    attestation_key_nonce = ""
    _usdid_header_cache = ""
    _usdid_header_expires_at = 0

    def get_usdid_settings(self) -> Dict[str, Any]:
        """
        Return the USDID key material for :meth:`get_settings`.

        Returns
        -------
        Dict
            Empty dictionary when no key has been generated yet.
        """
        if not self.usdid_private_key:
            return {}
        return {
            "usdid": self.usdid,
            "kid": self.usdid_kid,
            "private_key": self.usdid_private_key,
            "registered": self.usdid_registered,
        }

    def set_usdid_settings(self, settings: Optional[Dict[str, Any]] = None) -> bool:
        """
        Restore the USDID key material saved by :meth:`get_usdid_settings`.

        Returns
        -------
        bool
            ``True`` when a stored key was restored.
        """
        settings = settings or {}
        self.usdid = settings.get("usdid", "")
        self.usdid_kid = settings.get("kid", "")
        self.usdid_private_key = settings.get("private_key", "")
        self.usdid_registered = bool(settings.get("registered"))
        self._usdid_header_cache = ""
        self._usdid_header_expires_at = 0
        return bool(self.usdid_private_key)

    def usdid_generate(self, force: bool = False) -> str:
        """
        Generate the local EC P-256 key used to sign ``X-Meta-Usdid``.

        Parameters
        ----------
        force: bool, optional
            Replace an existing key instead of keeping it.

        Returns
        -------
        str
            USDID identifier (``sub`` of the signed token).
        """
        if self.usdid_private_key and not force:
            return self.usdid
        key = ECC.generate(curve="P-256")
        self.usdid_private_key = key.export_key(format="PEM")
        self.usdid = str(uuid4())
        self.usdid_kid = _b64u(get_random_bytes(32))
        self.usdid_registered = False
        self._usdid_header_cache = ""
        self._usdid_header_expires_at = 0
        return self.usdid

    def _usdid_key(self) -> ECC.EccKey:
        if not self.usdid_private_key:
            self.usdid_generate()
        return ECC.import_key(self.usdid_private_key)

    def _usdid_sign(self, message: str) -> bytes:
        signer = DSS.new(self._usdid_key(), "fips-186-3", encoding="der")
        return signer.sign(SHA256.new(message.encode()))

    @property
    def usdid_public_key(self) -> str:
        """Base64url (unpadded) DER SubjectPublicKeyInfo of the USDID key"""
        return _b64u(self._usdid_key().public_key().export_key(format="DER"))

    def usdid_header(self, ttl: int = USDID_TOKEN_TTL) -> str:
        """
        Build the ``X-Meta-Usdid`` header value.

        Format is ``{usdid}.{expires_at}.{public_key}.{signature}`` where the
        signature is ECDSA P-256/SHA-256 over the first three parts joined by
        dots. The value is cached until shortly before it expires, matching the
        app, which keeps one signed token per hour.

        Returns
        -------
        str
            Header value.
        """
        now = int(time.time())
        if self._usdid_header_cache and self._usdid_header_expires_at - now > USDID_REFRESH_MARGIN:
            return self._usdid_header_cache
        expires_at = now + ttl
        signed_part = f"{self.usdid}.{expires_at}.{self.usdid_public_key}"
        value = f"{signed_part}.{_b64u(self._usdid_sign(signed_part))}"
        self._usdid_header_cache = value
        self._usdid_header_expires_at = expires_at
        return value

    def usdid_registration_token(self, ttl: int = USDID_TOKEN_TTL) -> str:
        """
        Build the JWS device token sent by ``IGUSDIDRegistrationMutation``.

        Returns
        -------
        str
            Base64url (unpadded) JWS object.
        """
        now = int(time.time())
        public_key_der = self._usdid_key().public_key().export_key(format="DER")
        payload = _b64u(
            dumps(
                {
                    "sub": self.usdid,
                    "iat": now,
                    "aud": self.app_id,
                    "exp": now + ttl,
                    "pub": base64.b64encode(public_key_der).decode(),
                    "alg": "ES256",
                }
            ).encode()
        )
        protected = _b64u(
            dumps(
                {
                    "typ": "JWT",
                    "alg": "ES256",
                    "kid": self.usdid_kid,
                    "aid": self.app_id,
                    "ver": "1",
                }
            ).encode()
        )
        signature = _b64u(self._usdid_sign(f"{protected}.{payload}"))
        token = {
            "payload": payload,
            "signatures": [{"protected": protected, "signature": signature}],
        }
        return _b64u(dumps(token).encode())

    def usdid_register(self, client_doc_id: str = USDID_REGISTRATION_CLIENT_DOC_ID) -> bool:
        """
        Register the local USDID key with Instagram.

        The app performs this once per install, before login, and sends
        ``X-Meta-Usdid`` on every request afterwards.

        Returns
        -------
        bool
            ``True`` when Instagram reports a successful registration.
        """
        if not self.usdid_private_key:
            self.usdid_generate()
        variables = {
            "input": {
                "usdid_token": {"sensitive_string_value": self.usdid_registration_token()},
                "fdid": {"sensitive_string_value": self.phone_id},
            }
        }
        result = self.private_graphql_www_request(
            "IGUSDIDRegistrationMutation",
            variables,
            client_doc_id=client_doc_id,
            domain=self.domain,
            extra_headers={
                "X-Root-Field-Name": "usdid_registration",
                "X-Graphql-Client-Library": "pando",
            },
        )
        registration = {}
        for key, value in (result.get("data") or {}).items():
            if "usdid_registration" in key and isinstance(value, dict):
                registration = value
                break
        self.usdid_registered = bool(registration.get("success"))
        return self.usdid_registered

    def attestation_create_android_keystore(self, key_hash: str = "") -> Dict:
        """
        Request the attestation nonces used by the login request.

        ``key_hash`` stays empty when no hardware keystore key was uploaded;
        Instagram still returns the nonces in that case.

        Returns
        -------
        Dict
            Raw Instagram response with ``challenge_nonce`` and ``key_nonce``.
        """
        result = self.private_request(
            "attestation/create_android_keystore/",
            data={"app_scoped_device_id": self.uuid, "key_hash": key_hash},
            with_signature=False,
            headers={"X-FB-Friendly-Name": "IgApi: attestation/create_android_keystore/"},
        )
        self.attestation_challenge_nonce = result.get("challenge_nonce") or ""
        self.attestation_key_nonce = result.get("key_nonce") or ""
        return result

    def attestation_params(self, challenge_nonce: str = "") -> str:
        """
        Build the ``X-IG-Attest-Params`` header value.

        Reproduces the error state the app reports when keystore signing is
        unavailable. Instagram accepts login requests in this state.

        Returns
        -------
        str
            Header value, or an empty string when no nonce is available.
        """
        nonce = challenge_nonce or self.attestation_challenge_nonce
        if not nonce:
            return ""
        return dumps(
            {
                "attestation": [
                    {
                        "version": 2,
                        "type": "keystore",
                        "errors": [ATTESTATION_KEYSTORE_ERROR],
                        "challenge_nonce": nonce,
                        "signed_nonce": "",
                        "key_hash": "",
                    }
                ]
            }
        )
