"""Run the real acme.sh DNS-persist paths against a local HTTPS ACME fixture."""
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "acme.sh"
THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class Acme(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, data=None, location=None):
        content = json.dumps(data).encode() if data is not None else b""
        self.send_response(status)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Replay-Nonce", str(len(self.server.calls) + 1))
        if location:
            self.send_header("Location", location)
        if data is not None:
            self.send_header("Content-Type", "application/json")
        self.end_headers()
        if content:
            self.wfile.write(content)

    def do_HEAD(self):
        self.reply(200)

    def do_GET(self):
        origin = self.server.url
        self.reply(200, {
            "newNonce": origin + "/nonce", "newAccount": origin + "/new-account",
            "newOrder": origin + "/new-order",
            "meta": self.server.meta,
        })

    def do_POST(self):
        envelope = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        header = json.loads(decode(envelope["protected"]))
        payload = decode(envelope["payload"])
        origin = self.server.url
        self.server.calls.append((self.path, header, payload))
        if self.path == "/new-account":
            self.server.jwk = header["jwk"]
            self.reply(201, {"status": "valid"}, origin + "/acct/123")
        elif self.path == "/acct/123":
            if self.server.redirect:
                self.reply(307, location=origin + "/redirect")
            else:
                self.reply(200, {"status": self.server.account_status})
        elif self.path == "/new-order":
            self.server.identifier = json.loads(payload)["identifiers"][0]["value"]
            self.reply(201, {"status": "pending", "authorizations": [origin + "/authz"],
                             "finalize": origin + "/finalize"}, origin + "/order")
        elif self.path == "/authz":
            identifier = self.server.identifier
            self.reply(200, {
                "identifier": {"type": "dns", "value": identifier.removeprefix("*.")},
                "status": "pending", "wildcard": identifier.startswith("*."),
                "challenges": [{
                    "url": origin + "/challenge", "status": "pending",
                    "type": "dns-persist-01", "issuerDomainNames": self.server.challenge_issuers,
                }],
            })
        elif self.path == "/challenge":
            # Stop here, after exercising the normal issue path including the real JWS.
            self.reply(400, {"type": "urn:ietf:params:acme:error:unauthorized", "detail": "fixture stop"})
        else:
            self.reply(404)


class DnsPersistTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="acme-dns-persist-test-")
        cls.addClassCleanup(cls.workspace.cleanup)
        cls.root = Path(cls.workspace.name)
        cls.key = cls.root / "fixture.key"
        cls.cert = cls.root / "fixture.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
             "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", str(cls.key), "-out", str(cls.cert)],
            check=True, capture_output=True,
        )

    def setUp(self):
        state = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(state.cleanup)
        self.state = Path(state.name)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Acme)
        self.addCleanup(self.server.server_close)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.server.url = f"https://127.0.0.1:{self.server.server_port}"
        self.server.calls = []
        self.server.meta = {
            "accountHashPrefix": self.server.url + "/%61ccount-hash/",
            "issuerDomainNames": ["ca.example"],
            "caaIdentities": ["CA.Example."],
        }
        self.server.challenge_issuers = ["ca.example"]
        self.server.account_status = "valid"
        self.server.redirect = False
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join, 2)
        self.addCleanup(self.server.shutdown)

    def client(self, *arguments):
        try:
            return subprocess.run(
                [os.getenv("ACME_TEST_SHELL", "sh"), str(SCRIPT), *arguments,
                 "--home", str(self.state), "--config-home", str(self.state),
                 "--server", self.server.url + "/directory", "--ca-bundle", str(self.cert)],
                text=True, capture_output=True, timeout=30,
            )
        except subprocess.TimeoutExpired as error:
            self.fail(f"ACME fixture timed out: {error.stdout!r} {error.stderr!r}")

    def generate(self, domain, *arguments):
        return self.client("--make-dns-persist-value", "-d", domain, *arguments)

    def expected_uri(self, domain):
        jwk = json.dumps(self.server.jwk, separators=(",", ":"), sort_keys=True).encode()
        key = b64(hashlib.sha256(jwk).digest()).encode()
        name = domain.encode()
        url = (self.server.url + "/acct/123").encode()
        return self.server.meta["accountHashPrefix"] + "sha-256/" + b64(
            hashlib.sha256(bytes([len(name)]) + name + key + url).digest()
        )

    def test_draft_vectors(self):
        for domain, digest in [
            ("example.com", "5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw"),
            ("*", "NpDnSwUthQK8zCgFdefYxAdAVPnygMLbs9US6oO-5ug"),
            ("xn--fa-hia.example", "dc3zyKBvsc9_vyWQoZSyM4fgcN0d7jnr61730r7ekAw"),
        ]:
            prefix = "https://ca.example/account-hash/"
            result = subprocess.check_output(
                [os.getenv("ACME_TEST_SHELL", "sh"), SCRIPT, "_dns_persist_hashed_uri", prefix,
                 domain, THUMBPRINT, "https://ca.example/acct/123"], text=True,
            )
            self.assertEqual(result.strip(), prefix + "sha-256/" + digest)

    def test_generation_binds_ancestor_and_authenticated_account(self):
        result = self.generate("App.Example.COM.", "--dns-persist-ancestor", "example.com",
                               "--dns-persist-days", "008")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("TXT persist domain:_validation-persist.example.com", result.stdout)
        self.assertIn("ca.example; accounturi=" + self.expected_uri("example.com"), result.stdout)
        self.assertRegex(result.stdout, r"; policy=wildcard; persistUntil=[0-9]+")
        [(path, header, payload)] = [call for call in self.server.calls if call[0].startswith("/acct/")]
        self.assertEqual(path, "/acct/123")
        self.assertEqual(payload, b"")
        self.assertEqual(header["kid"], self.server.url + path)
        self.assertEqual(header["url"], self.server.url + path)
        self.assertNotIn("accounturi=" + header["kid"], result.stdout.replace("/%61ccount-hash/", ""))
        opted_out = self.generate("*.example.com", "--dns-persist-opt-out")
        self.assertEqual(opted_out.returncode, 0, opted_out.stderr + opted_out.stdout)
        self.assertIn(self.expected_uri("*") + "; policy=wildcard", opted_out.stdout)
        self.assertEqual(sum(path == "/new-account" for path, *_ in self.server.calls), 1)

    def test_missing_or_unsafe_metadata_cannot_generate_a_record(self):
        for meta in (
            {"caaIdentities": ["ca.example"]},
            {"accountHashPrefix": "https://example.co/x;y/", "issuerDomainNames": ["ca.example"]},
            {"accountHashPrefix": self.server.url + "/hash/", "issuerDomainNames": ["ca.example,b.example"]},
            {"accountHashPrefix": self.server.url + "/hash/", "issuerDomainNames": ["ca.example"] * 11},
        ):
            self.server.meta = meta
            result = self.generate("example.com")
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertNotIn("TXT persist value", result.stdout)
        self.assertEqual(self.server.calls, [])

    def test_rejects_redirect_and_inactive_account(self):
        self.server.redirect = True
        result = self.generate("example.com")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("/redirect", [path for path, *_ in self.server.calls])
        self.server.redirect = False
        self.server.account_status = "deactivated"
        result = self.generate("example.com")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("TXT persist value", result.stdout)

    def test_issue_sends_ancestor_or_empty_object_and_rejects_bad_issuer(self):
        for options, expected in [
            (["--dns-persist-ancestor", "example.com"], {"ancestorDomain": "example.com"}),
            ([], {}),
        ]:
            result = self.client("--issue", "--dns-persist", "-d", "app.example.com", *options)
            self.assertIn("fixture stop", result.stderr, result.stdout)
            challenge = [json.loads(payload) for path, _, payload in self.server.calls if path == "/challenge"]
            self.assertEqual(challenge[-1], expected)
            conf = next(self.state.glob("app.example.com*/app.example.com.conf")).read_text()
            if expected:
                self.assertIn("Le_DnsPersistAncestor='example.com'", conf)
                renewed = self.client("--renew", "--force", "--ecc", "-d", "app.example.com")
                self.assertIn("fixture stop", renewed.stderr, renewed.stdout)
                self.assertEqual(
                    [json.loads(payload) for path, _, payload in self.server.calls if path == "/challenge"][-1],
                    expected,
                )
            else:
                self.assertNotIn("Le_DnsPersistAncestor=", conf)
        previous = len([path for path, *_ in self.server.calls if path == "/challenge"])
        self.server.challenge_issuers = ["unexpected.example"]
        result = self.client("--issue", "--dns-persist", "-d", "app.example.com")
        self.assertIn("Cannot use the draft-03 persistent DNS challenge", result.stderr, result.stdout)
        self.assertEqual(len([path for path, *_ in self.server.calls if path == "/challenge"]), previous)


if __name__ == "__main__":
    unittest.main()
