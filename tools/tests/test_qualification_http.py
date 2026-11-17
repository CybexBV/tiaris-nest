import http.client
import importlib.util
import io
import json
from pathlib import Path
import ssl
import unittest
import urllib.error
import urllib.request
from unittest.mock import Mock


ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


HTTP = module('qualification_http_test', ROOT /
              'nixos-appliance/qualification/qualification_http.py')


class Response:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def read(self, size):
        return self.value[:size]


def request(method='GET'):
    return urllib.request.Request('https://dev.example.test/v1/qualification',
                                  method=method)


class QualificationHttpTests(unittest.TestCase):
    def test_readonly_transient_failures_retry_and_capture_a_fresh_response(self):
        expected = {'state': 'ready'}
        client = Mock()
        client.open.side_effect = [
            urllib.error.URLError(ssl.SSLEOFError('TLS peer closed unexpectedly')),
            urllib.error.URLError(TimeoutError('handshake timed out')),
            http.client.IncompleteRead(b'{"partial"'),
            Response(json.dumps(expected).encode()),
        ]
        sleep = Mock()

        self.assertEqual(HTTP.request_json(client, request(), timeout=10,
                                           max_bytes=1024, sleep=sleep), expected)
        self.assertEqual(client.open.call_count, HTTP.GET_ATTEMPTS)
        self.assertEqual(sleep.call_count, HTTP.GET_ATTEMPTS - 1)

    def test_only_selected_transient_http_statuses_are_retried(self):
        for status in (408, 429, 502, 503, 504, 525):
            with self.subTest(status=status):
                client = Mock()
                error = urllib.error.HTTPError(
                    request().full_url, status, 'transient', {}, io.BytesIO())
                client.open.side_effect = [
                    error,
                    Response(b'{"ok":true}'),
                ]
                self.assertEqual(HTTP.request_json(client, request(), timeout=10,
                                                   max_bytes=1024, sleep=Mock()), {'ok': True})
                self.assertEqual(client.open.call_count, 2)
                self.assertTrue(error.fp.closed)

        client = Mock()
        client.open.side_effect = urllib.error.HTTPError(
            request().full_url, 500, 'not selected', {}, io.BytesIO())
        with self.assertRaises(urllib.error.HTTPError):
            HTTP.request_json(client, request(), timeout=10, max_bytes=1024)
        client.open.assert_called_once()

    def test_gateway_retry_does_not_retry_mutations_or_invalid_origin_certificates(self):
        for method, status in (('POST', 525), ('GET', 526)):
            with self.subTest(method=method, status=status):
                client = Mock()
                client.open.side_effect = urllib.error.HTTPError(
                    request().full_url, status, 'gateway failure', {}, io.BytesIO())
                with self.assertRaises(urllib.error.HTTPError):
                    HTTP.request_json(client, request(method), timeout=10,
                                      max_bytes=1024, sleep=Mock())
                client.open.assert_called_once()

    def test_response_cap_is_not_retried(self):
        client = Mock()
        client.open.return_value = Response(b'123456')
        with self.assertRaisesRegex(ValueError, 'exceeded its bound'):
            HTTP.request_json(client, request(), timeout=10, max_bytes=4)
        client.open.assert_called_once()

    def test_transient_retry_count_is_bounded(self):
        client = Mock()
        client.open.side_effect = urllib.error.URLError(
            TimeoutError('handshake timed out'))
        sleep = Mock()
        with self.assertRaises(urllib.error.URLError):
            HTTP.request_json(client, request(), timeout=10,
                              max_bytes=1024, sleep=sleep)
        self.assertEqual(client.open.call_count, HTTP.GET_ATTEMPTS)
        self.assertEqual(sleep.call_count, HTTP.GET_ATTEMPTS - 1)

    def test_mutation_response_loss_is_not_retried(self):
        client = Mock()
        client.open.side_effect = http.client.IncompleteRead(b'{"accepted":true')
        with self.assertRaises(http.client.IncompleteRead):
            HTTP.request_json(client, request('POST'), timeout=10, max_bytes=1024)
        client.open.assert_called_once()

    def test_redirect_refusal_and_auth_failure_are_not_retried(self):
        failures = [
            ValueError('Qualification API redirect refused'),
            urllib.error.HTTPError(request().full_url, 403, 'forbidden', {}, io.BytesIO()),
        ]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                client = Mock()
                client.open.side_effect = failure
                with self.assertRaises(type(failure)):
                    HTTP.request_json(client, request(), timeout=10, max_bytes=1024)
                client.open.assert_called_once()

    def test_certificate_verification_failure_is_not_retried(self):
        client = Mock()
        client.open.side_effect = urllib.error.URLError(
            ssl.SSLCertVerificationError('certificate verify failed'))
        with self.assertRaises(urllib.error.URLError):
            HTTP.request_json(client, request(), timeout=10, max_bytes=1024)
        client.open.assert_called_once()


if __name__ == '__main__':
    unittest.main()
