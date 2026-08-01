import base64
import json

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS

from tests.helpers import *


def _b64u_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class DeviceAttestationRegressionTestCase(unittest.TestCase):
    def build_client(self):
        client = Client()
        client.uuid = "00000000-0000-4000-8000-000000000000"
        client.phone_id = "11111111-1111-4111-8111-111111111111"
        client.bloks_versioning_id = "bloks-version"
        return client

    def test_usdid_header_is_signed_over_uuid_ts_pubkey(self):
        client = self.build_client()
        client.usdid_generate()
        value = client.usdid_header()
        parts = value.split(".")
        self.assertEqual(len(parts), 4)
        usdid, ts, pubkey, signature = parts
        self.assertEqual(usdid, client.usdid)
        self.assertTrue(ts.isdigit())
        public_key = ECC.import_key(_b64u_decode(pubkey))
        verifier = DSS.new(public_key, "fips-186-3", encoding="der")
        # Raises when the signature does not cover "{usdid}.{ts}.{pubkey}"
        verifier.verify(SHA256.new(f"{usdid}.{ts}.{pubkey}".encode()), _b64u_decode(signature))

    def test_usdid_header_absent_from_base_headers_until_generated(self):
        client = self.build_client()
        self.assertNotIn("X-Meta-Usdid", client.base_headers)
        client.usdid_generate()
        self.assertEqual(client.base_headers["X-Meta-Usdid"], client.usdid_header())

    def test_usdid_header_is_cached_between_calls(self):
        client = self.build_client()
        client.usdid_generate()
        self.assertEqual(client.usdid_header(), client.usdid_header())

    def test_registration_token_is_valid_es256_jws(self):
        client = self.build_client()
        client.usdid_generate()
        token = json.loads(_b64u_decode(client.usdid_registration_token()))
        payload = json.loads(_b64u_decode(token["payload"]))
        protected = json.loads(_b64u_decode(token["signatures"][0]["protected"]))
        self.assertEqual(payload["sub"], client.usdid)
        self.assertEqual(payload["aud"], client.app_id)
        self.assertEqual(payload["exp"] - payload["iat"], 3600)
        self.assertEqual(protected["alg"], "ES256")
        self.assertEqual(protected["kid"], client.usdid_kid)
        public_key = ECC.import_key(base64.b64decode(payload["pub"]))
        verifier = DSS.new(public_key, "fips-186-3", encoding="der")
        signing_input = f"{token['signatures'][0]['protected']}.{token['payload']}"
        verifier.verify(SHA256.new(signing_input.encode()), _b64u_decode(token["signatures"][0]["signature"]))

    def test_usdid_register_marks_registered_and_sends_token(self):
        client = self.build_client()
        captured = {}

        def fake_graphql(friendly_name, variables=None, **kwargs):
            captured["friendly_name"] = friendly_name
            captured["variables"] = variables
            captured["kwargs"] = kwargs
            return {"data": {"1$usdid_registration(data:$input)": {"success": True}}}

        with mock.patch.object(client, "private_graphql_www_request", side_effect=fake_graphql):
            self.assertTrue(client.usdid_register())

        self.assertTrue(client.usdid_registered)
        self.assertEqual(captured["friendly_name"], "IGUSDIDRegistrationMutation")
        self.assertEqual(
            captured["variables"]["input"]["fdid"]["sensitive_string_value"],
            client.phone_id,
        )
        self.assertTrue(captured["variables"]["input"]["usdid_token"]["sensitive_string_value"])

    def test_attestation_params_reports_keystore_error_state(self):
        client = self.build_client()
        params = json.loads(client.attestation_params("NONCE123"))
        attestation = params["attestation"][0]
        self.assertEqual(attestation["type"], "keystore")
        self.assertEqual(attestation["errors"], [-1013])
        self.assertEqual(attestation["challenge_nonce"], "NONCE123")
        self.assertEqual(attestation["signed_nonce"], "")

    def test_attestation_params_empty_without_nonce(self):
        client = self.build_client()
        self.assertEqual(client.attestation_params(), "")

    def test_zca_header_reports_time_hash_without_signing(self):
        client = self.build_client()
        value = json.loads(base64.b64decode(client.zca_header()))
        android = value["android"]
        aka = android["aka"]
        data_to_sign = json.loads(aka["dataToSign"])
        self.assertTrue(data_to_sign["time"].isdigit())
        digest = SHA256.new(data_to_sign["time"].encode()).digest()
        expected_hash = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        self.assertEqual(data_to_sign["hash"], expected_hash)
        self.assertEqual(aka["signedData"], "")
        self.assertEqual(aka["keyHash"], "")
        self.assertEqual(android["gpia"], {"token": "", "errors": ["PLAY_INTEGRITY_DISABLED_BY_CONFIG"]})

    def test_attestation_create_android_keystore_stores_nonces(self):
        client = self.build_client()
        response = {"challenge_nonce": "chal", "key_nonce": "keyn", "status": "ok"}

        with mock.patch.object(client, "private_request", return_value=response) as private_request:
            result = client.attestation_create_android_keystore()

        self.assertEqual(result, response)
        self.assertEqual(client.attestation_challenge_nonce, "chal")
        self.assertEqual(client.attestation_key_nonce, "keyn")
        data = private_request.call_args.kwargs["data"]
        self.assertEqual(data["app_scoped_device_id"], client.uuid)
        self.assertEqual(data["key_hash"], "")

    def test_usdid_settings_roundtrip(self):
        client = self.build_client()
        client.usdid_generate()
        client.usdid_registered = True
        settings = client.get_usdid_settings()

        restored = self.build_client()
        self.assertTrue(restored.set_usdid_settings(settings))
        self.assertEqual(restored.usdid, client.usdid)
        self.assertEqual(restored.usdid_public_key, client.usdid_public_key)
        self.assertTrue(restored.usdid_registered)

    def test_get_settings_includes_usdid(self):
        client = self.build_client()
        client.usdid_generate()
        settings = client.get_settings()
        self.assertIn("usdid", settings)
        self.assertEqual(settings["usdid"]["usdid"], client.usdid)


class CaaLoginRegressionTestCase(unittest.TestCase):
    def build_client(self):
        client = Client()
        client.uuid = "00000000-0000-4000-8000-000000000000"
        client.phone_id = "11111111-1111-4111-8111-111111111111"
        client.bloks_versioning_id = "bloks-version"
        client.username = "example_user"
        client.password = "dummy"
        return client

    def test_extract_aac_from_lispy_initial(self):
        client = self.build_client()
        aac_json = '{"aac_init_timestamp":1785582449,"aacjid":"99b3","aaccs":"tMsT"}'
        escaped = json.dumps(aac_json)  # wrap as a JSON string literal
        response = {
            "layout": {
                "bloks_payload": {
                    "data": [
                        {
                            "id": "x",
                            "type": "gs",
                            "data": {
                                "key": "CAA_ACCOUNT_ACCESS_CONTEXT:aac",
                                "mode": "p",
                                "initial_lispy": f"\t(fhy {escaped})",
                            },
                        }
                    ]
                }
            }
        }
        extracted = client.bloks_extract_aac(response)
        self.assertEqual(json.loads(extracted)["aaccs"], "tMsT")

    def test_prepare_runs_full_device_sequence(self):
        client = self.build_client()
        order = []

        def fake_register():
            order.append("usdid_register")
            client.usdid_registered = True
            return True

        def fake_keystore(key_hash=""):
            order.append("attestation")
            client.attestation_challenge_nonce = "chal"
            return {"challenge_nonce": "chal"}

        def fake_pcdr(**kwargs):
            order.append("process_client_data")
            client.caa_aac = '{"aaccs":"x"}'
            return {}

        def fake_oauth(**kwargs):
            order.append("oauth_fetch")
            return {}

        with mock.patch.object(client, "usdid_register", side_effect=fake_register), mock.patch.object(
            client, "attestation_create_android_keystore", side_effect=fake_keystore
        ), mock.patch.object(
            client, "bloks_caa_login_process_client_data", side_effect=fake_pcdr
        ), mock.patch.object(
            client, "bloks_caa_login_oauth_token_fetch", side_effect=fake_oauth
        ):
            self.assertTrue(client.bloks_caa_login_prepare())

        self.assertEqual(order, ["usdid_register", "attestation", "process_client_data", "oauth_fetch"])

    def test_send_request_uses_server_issued_aac_and_attest_header(self):
        client = self.build_client()
        client.usdid_generate()
        client.caa_aac = '{"aac_init_timestamp":1,"aacjid":"j","aaccs":"server-aac"}'
        client.attestation_challenge_nonce = "chal-nonce"
        captured = {}

        def fake_private_request(endpoint, data=None, *args, **kwargs):
            captured["endpoint"] = endpoint
            captured["data"] = data
            captured["headers"] = kwargs.get("headers")
            return {"status": "ok"}

        with mock.patch.object(client, "private_request", side_effect=fake_private_request):
            client.bloks_caa_login_send_request("dummy_password")

        params = json.loads(captured["data"]["params"])
        self.assertEqual(params["client_input_params"]["aac"], client.caa_aac)
        self.assertIn("X-IG-Attest-Params", captured["headers"])
        attest = json.loads(captured["headers"]["X-IG-Attest-Params"])
        self.assertEqual(attest["attestation"][0]["challenge_nonce"], "chal-nonce")
        self.assertIn("X-Meta-Zca", captured["headers"])
        json.loads(base64.b64decode(captured["headers"]["X-Meta-Zca"]))  # decodes without raising

    def test_bloks_caa_login_applies_embedded_login_response(self):
        client = self.build_client()
        authorization = "Bearer IGT:2:token"
        login_response = json.dumps(
            {
                "login_response": json.dumps({"status": "ok", "logged_in_user": {"pk": 123}}),
                "headers": json.dumps({"IG-Set-Authorization": authorization}),
            }
        )
        send_result = {"layout": {"bloks_payload": {"action": f'(foo {json.dumps(login_response)})'}}}

        with mock.patch.object(client, "bloks_caa_login_prepare", return_value=True), mock.patch.object(
            client, "bloks_caa_login_send_request", return_value=send_result
        ), mock.patch.object(client, "parse_authorization", return_value={"ds_user_id": "123"}) as parse_auth:
            outcome = client.bloks_caa_login()

        self.assertTrue(outcome["logged_in"])
        self.assertEqual(outcome["two_step_verification_context"], "")
        parse_auth.assert_called_once_with(authorization)


class CaaTwoStepVerificationRegressionTestCase(unittest.TestCase):
    """CAA "Verify your profile" code challenge (ap.two_step_verification flow)."""

    ENTRYPOINT = "com.bloks.www.ap.two_step_verification.entrypoint_async"
    CODE_ENTRY = "com.bloks.www.ap.two_step_verification.code_entry"
    CODE_ENTRY_ASYNC = "com.bloks.www.ap.two_step_verification.code_entry_async"

    def build_client(self):
        client = Client()
        client.uuid = "00000000-0000-4000-8000-000000000000"
        client.phone_id = "11111111-1111-4111-8111-111111111111"
        client.bloks_versioning_id = "bloks-version"
        client.username = "example_user"
        client.password = "dummy"
        client.caa_aac = '{"aac_init_timestamp":1,"aacjid":"j","aaccs":"srv"}'
        return client

    def _action(self, app_id, context_data):
        # Mirrors the real program shape: the next app_id is followed by its
        # params map with context_data as the first key.
        return {
            "layout": {
                "bloks_payload": {
                    "action": (
                        f'... "{app_id}" (f4i (dkc "context_data" "device_id") '
                        f'(dkc "{context_data}" "dev"))'
                    )
                }
            }
        }

    def test_needs_two_step_detects_verify_profile_challenge(self):
        client = self.build_client()
        challenge = self._action(self.ENTRYPOINT, "ctx-entry|aplc")
        clean = {"layout": {"bloks_payload": {"action": "(foo)"}}}
        self.assertTrue(client.bloks_caa_login_needs_two_step(challenge))
        self.assertFalse(client.bloks_caa_login_needs_two_step(clean))

    def test_extract_context_data_is_app_id_exact(self):
        client = self.build_client()
        # code_entry must not match code_entry_async / code_entry_help.
        action = {
            "layout": {
                "bloks_payload": {
                    "action": (
                        '"com.bloks.www.ap.two_step_verification.code_entry_help" '
                        '(f4i (dkc "context_data") (dkc "help-ctx|aplc")) '
                        '"com.bloks.www.ap.two_step_verification.code_entry" '
                        '(f4i (dkc "context_data") (dkc "entry-ctx|aplc"))'
                    )
                }
            }
        }
        self.assertEqual(client.bloks_extract_context_data(action, self.CODE_ENTRY), "entry-ctx|aplc")

    def test_extract_context_data_reads_ft_templates(self):
        client = self.build_client()
        # code_entry_async context_data lives in the ft template map, not action.
        result = {
            "layout": {
                "bloks_payload": {
                    "action": "(noop)",
                    "ft": {
                        "tpl": (
                            '"com.bloks.www.ap.two_step_verification.code_entry_async" '
                            '(f4i (dkc "context_data" "device_id") (dkc "submit-ctx|aplc" "d"))'
                        )
                    },
                }
            }
        }
        self.assertEqual(client.bloks_extract_context_data(result, self.CODE_ENTRY_ASYNC), "submit-ctx|aplc")

    def test_resolve_two_step_chains_context_data_and_submits_code(self):
        client = self.build_client()
        send_result = self._action(self.ENTRYPOINT, "ctx1|aplc")
        entry_result = self._action(self.CODE_ENTRY, "ctx2|aplc")
        code_entry_result = self._action(self.CODE_ENTRY_ASYNC, "ctx3|aplc")
        authorization = "Bearer IGT:2:token"
        embedded = json.dumps(
            {
                "login_response": json.dumps({"status": "ok", "logged_in_user": {"pk": 99}}),
                "headers": json.dumps({"IG-Set-Authorization": authorization}),
            }
        )
        submit_result = {"layout": {"bloks_payload": {"action": f"(x {json.dumps(embedded)})"}}}
        calls = []

        def entrypoint(context_data, **kwargs):
            calls.append(("entrypoint", context_data))
            return entry_result

        def code_entry(context_data, **kwargs):
            calls.append(("code_entry", context_data))
            return code_entry_result

        def submit(context_data, code, **kwargs):
            calls.append(("submit", context_data, code))
            return submit_result

        with mock.patch.object(client, "bloks_ap_two_step_verification_entrypoint", side_effect=entrypoint), \
                mock.patch.object(client, "bloks_ap_two_step_verification_code_entry", side_effect=code_entry), \
                mock.patch.object(client, "bloks_ap_two_step_verification_submit_code", side_effect=submit), \
                mock.patch.object(client, "parse_authorization", return_value={"ds_user_id": "99"}):
            outcome = client.bloks_caa_resolve_two_step_verification(send_result, verification_code="098728")

        self.assertTrue(outcome["logged_in"])
        self.assertEqual(calls[0], ("entrypoint", "ctx1|aplc"))
        self.assertEqual(calls[1], ("code_entry", "ctx2|aplc"))
        self.assertEqual(calls[2], ("submit", "ctx3|aplc", "098728"))

    def test_resolve_uses_challenge_code_handler_when_no_code_given(self):
        client = self.build_client()
        send_result = self._action(self.ENTRYPOINT, "ctx1|aplc")
        entry_result = self._action(self.CODE_ENTRY, "ctx2|aplc")
        code_entry_result = self._action(self.CODE_ENTRY_ASYNC, "ctx3|aplc")
        submitted = {}

        client.challenge_code_handler = lambda username, choice: "654321"

        def submit(context_data, code, **kwargs):
            submitted["code"] = code
            return {"layout": {"bloks_payload": {"action": "(noop)"}}}

        with mock.patch.object(client, "bloks_ap_two_step_verification_entrypoint", return_value=entry_result), \
                mock.patch.object(client, "bloks_ap_two_step_verification_code_entry", return_value=code_entry_result), \
                mock.patch.object(client, "bloks_ap_two_step_verification_submit_code", side_effect=submit), \
                mock.patch.object(client, "bloks_apply_login_response", return_value=False):
            client.bloks_caa_resolve_two_step_verification(send_result)

        self.assertEqual(submitted["code"], "654321")

    def test_caa_login_steps_are_marked_prelogin(self):
        # CAA login/challenge requests must run as pre-login requests so they are
        # valid before self.user_id is set (and skip the pre-login throttle).
        client = self.build_client()
        client.mid = "mid-1"
        client.caa_aac = '{"aac":"x"}'
        client.attestation_challenge_nonce = "nonce"
        seen = []

        def fake_private_request(endpoint, data=None, *args, **kwargs):
            seen.append((endpoint, kwargs.get("login")))
            return {"status": "ok"}

        with mock.patch.object(client, "private_request", side_effect=fake_private_request):
            client.bloks_caa_login_send_request("dummy_password")
            client.bloks_ap_two_step_verification_entrypoint("ctx1")
            client.bloks_ap_two_step_verification_code_entry("ctx2")
            client.bloks_ap_two_step_verification_submit_code("ctx3", "098728")

        self.assertTrue(seen, "no requests captured")
        for endpoint, login in seen:
            self.assertTrue(login, f"{endpoint} was not sent as a pre-login request")

    def test_submit_code_payload_shape(self):
        client = self.build_client()
        client.mid = "mid-123"
        captured = {}

        def fake_async(action, params, **kwargs):
            captured["action"] = action
            captured["params"] = params
            return {"status": "ok"}

        with mock.patch.object(client, "bloks_async_action", side_effect=fake_async):
            client.bloks_ap_two_step_verification_submit_code("ctx3|aplc", "098728")

        self.assertEqual(captured["action"], self.CODE_ENTRY_ASYNC)
        cip = captured["params"]["client_input_params"]
        self.assertEqual(cip["code"], "098728")
        self.assertEqual(cip["aac"], client.caa_aac)
        self.assertEqual(cip["machine_id"], "mid-123")
        self.assertEqual(cip["family_device_id"], client.phone_id)
        self.assertEqual(captured["params"]["server_params"]["context_data"], "ctx3|aplc")
