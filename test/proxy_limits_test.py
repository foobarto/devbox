"""Bounded local fixtures for proxy admission, retention, and audit integrity."""
import importlib.util
import io
import json
import os
import socket
import tempfile
import threading
import time
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, call, patch


_STATE = tempfile.TemporaryDirectory(prefix="devbox-proxy-limits-test-")
_MODULE = Path(__file__).parents[1] / "proxy" / "devbox-ai-proxy.py"
with patch.dict(os.environ, {
    "DEVBOX_PROXY_STATE_DIR": _STATE.name,
    "DEVBOX_PROXY_AUDIT_PATH": str(Path(_STATE.name) / "audit.jsonl"),
    "DEVBOX_PROXY_CONFIG": str(_MODULE.parent / "proxy.config.example.json"),
}):
    _SPEC = importlib.util.spec_from_file_location("devbox_proxy_limits", _MODULE)
    proxy = importlib.util.module_from_spec(_SPEC)
    _SPEC.loader.exec_module(proxy)


def headers(**values):
    result = Message()
    for key, value in values.items():
        result[key.replace("_", "-")] = str(value)
    return result


class AdmissionTests(TestCase):
    def test_server_rejects_before_thread_creation_and_releases_sources(self):
        server = proxy.BoundedHTTPServer.__new__(proxy.BoundedHTTPServer)
        server._admission_lock = threading.Lock()
        server._connections = {}
        server._deadline_sockets = {}
        server._sources = {}
        server.shutdown_request = Mock()
        first, second, third = Mock(), Mock(), Mock()
        with patch.object(proxy, "MAX_WORKERS", 2), \
             patch.object(proxy, "MAX_WORKERS_PER_SOURCE", 1), \
             patch.object(proxy.ThreadingHTTPServer, "process_request") as spawn:
            server.process_request(first, ("source-a", 1))
            server.process_request(second, ("source-a", 2))
            self.assertEqual(spawn.call_count, 1)
            server.shutdown_request.assert_called_once_with(second)
            server.process_request(second, ("source-b", 2))
            server.process_request(third, ("source-c", 3))
            self.assertEqual(spawn.call_count, 2)
            server.shutdown_request.assert_called_with(third)
            server._release_connection(first)
            server._release_connection(second)
            self.assertEqual(server._sources, {})
            self.assertEqual(server._connections, {})

    def test_stalled_chunked_body_leaves_budget_for_another_box(self):
        class StalledChunk:
            requested = 0

            def readline(self, _limit):
                return b"64\r\n"

            def read(self, size):
                self.requested = size
                raise TimeoutError("fixture stall")

        stalled = StalledChunk()
        with patch.object(proxy, "MAX_REQUEST_BODY_BYTES", 100), \
             patch.object(proxy, "MAX_BUFFERED_BODY_BYTES", 300), \
             patch.object(proxy, "MAX_BUFFERED_BODY_BYTES_PER_BOX", 100), \
             patch.object(proxy, "_BODY_READ_CHUNK_BYTES", 10), \
             patch.object(proxy, "_BUFFERED_BODY_BYTES", 0), \
             patch.object(proxy, "_BOX_BUFFERED_BODY_BYTES", {}):
            first = proxy.reserve_body_bytes("box-a")
            with self.assertRaises(TimeoutError):
                proxy.read_request_body(headers(Transfer_Encoding="chunked"), stalled, first)
            self.assertEqual(stalled.requested, 10)
            self.assertEqual(first.total_bytes, 10)

            second = proxy.reserve_body_bytes("box-b")
            body = proxy.read_request_body(
                headers(Content_Length=100), io.BytesIO(b"b" * 100), second,
            )
            self.assertEqual(body, b"b" * 100)
            self.assertEqual(proxy._BUFFERED_BODY_BYTES, 110)
            proxy.release_body_bytes(second)
            proxy.release_body_bytes(first)
            self.assertEqual(proxy._BUFFERED_BODY_BYTES, 0)
            self.assertEqual(proxy._BOX_BUFFERED_BODY_BYTES, {})

    def test_chunked_accounting_shrinks_after_temporary_decoder_copies(self):
        encoded = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        with patch.object(proxy, "MAX_REQUEST_BODY_BYTES", 100), \
             patch.object(proxy, "MAX_BUFFERED_BODY_BYTES", 300), \
             patch.object(proxy, "MAX_BUFFERED_BODY_BYTES_PER_BOX", 100), \
             patch.object(proxy, "_BODY_READ_CHUNK_BYTES", 4), \
             patch.object(proxy, "_BUFFERED_BODY_BYTES", 0), \
             patch.object(proxy, "_BOX_BUFFERED_BODY_BYTES", {}):
            reservation = proxy.reserve_body_bytes("box-a")
            body = proxy.read_request_body(
                headers(Transfer_Encoding="chunked"), io.BytesIO(encoded), reservation,
            )
            self.assertEqual(body, b"hello world")
            self.assertEqual(reservation.buffered_bytes, 11)
            self.assertEqual(reservation.total_bytes, 11)
            self.assertEqual(proxy._BUFFERED_BODY_BYTES, 11)
            self.assertEqual(proxy._BOX_BUFFERED_BODY_BYTES, {"box-a": 11})
            proxy.release_body_bytes(reservation)
            self.assertEqual(proxy._BUFFERED_BODY_BYTES, 0)
            self.assertEqual(proxy._BOX_BUFFERED_BODY_BYTES, {})

    def test_handler_reads_a_legitimate_chunked_body_with_box_accounting(self):
        handler = proxy.Handler.__new__(proxy.Handler)
        handler.headers = headers(Transfer_Encoding="chunked")
        handler.rfile = io.BytesIO(b"5\r\nhello\r\n0\r\n\r\n")
        handler.connection = Mock()
        handler._deadline = Mock()
        handler._admitted_box = "box-a"
        handler._body_reservation = None
        with patch.object(proxy, "MAX_REQUEST_BODY_BYTES", 100), \
             patch.object(proxy, "MAX_BUFFERED_BODY_BYTES", 300), \
             patch.object(proxy, "MAX_BUFFERED_BODY_BYTES_PER_BOX", 100), \
             patch.object(proxy, "_BODY_READ_CHUNK_BYTES", 4), \
             patch.object(proxy, "_BUFFERED_BODY_BYTES", 0), \
             patch.object(proxy, "_BOX_BUFFERED_BODY_BYTES", {}):
            self.assertEqual(handler._read_body(), b"hello")
            self.assertEqual(handler._body_reservation.buffered_bytes, 5)
            self.assertEqual(proxy._BOX_BUFFERED_BODY_BYTES, {"box-a": 5})
            handler._deadline.assert_has_calls([
                call(proxy.BODY_TIMEOUT_SECONDS),
                call(proxy.MAX_CONNECTION_SECONDS),
            ])
            handler.connection.settimeout.assert_called_once_with(proxy.STREAM_IDLE_TIMEOUT_SECONDS)
            proxy.release_body_bytes(handler._body_reservation)
            self.assertEqual(proxy._BUFFERED_BODY_BYTES, 0)
            self.assertEqual(proxy._BOX_BUFFERED_BODY_BYTES, {})

    def test_nearly_complete_chunk_cannot_hold_temporary_copy_budget(self):
        class NearlyCompleteChunk:
            remaining = bytearray(b"a" * 90)

            def readline(self, _limit):
                return b"64\r\n"

            def read(self, size):
                if not self.remaining:
                    raise TimeoutError("fixture stall")
                result = bytes(self.remaining[:size])
                del self.remaining[:size]
                return result

        with patch.object(proxy, "MAX_REQUEST_BODY_BYTES", 100), \
             patch.object(proxy, "MAX_BUFFERED_BODY_BYTES", 300), \
             patch.object(proxy, "MAX_BUFFERED_BODY_BYTES_PER_BOX", 100), \
             patch.object(proxy, "_BODY_READ_CHUNK_BYTES", 10), \
             patch.object(proxy, "_BUFFERED_BODY_BYTES", 0), \
             patch.object(proxy, "_BOX_BUFFERED_BODY_BYTES", {}):
            first = proxy.reserve_body_bytes("box-a")
            with self.assertRaises(TimeoutError):
                proxy.read_request_body(
                    headers(Transfer_Encoding="chunked"), NearlyCompleteChunk(), first,
                )
            self.assertEqual(first.buffered_bytes, 100)
            self.assertEqual(first.total_bytes, 100)

            second = proxy.reserve_body_bytes("box-b")
            body = proxy.read_request_body(headers(Content_Length=1), io.BytesIO(b"b"), second)
            self.assertEqual(body, b"b")
            proxy.release_body_bytes(second)
            proxy.release_body_bytes(first)
            self.assertEqual(proxy._BUFFERED_BODY_BYTES, 0)
            self.assertEqual(proxy._BOX_BUFFERED_BODY_BYTES, {})

    def test_per_box_body_budget_preserves_global_capacity(self):
        with patch.object(proxy, "MAX_REQUEST_BODY_BYTES", 100), \
             patch.object(proxy, "MAX_BUFFERED_BODY_BYTES", 300), \
             patch.object(proxy, "MAX_BUFFERED_BODY_BYTES_PER_BOX", 100), \
             patch.object(proxy, "_BUFFERED_BODY_BYTES", 0), \
             patch.object(proxy, "_BOX_BUFFERED_BODY_BYTES", {}):
            first = proxy.reserve_body_bytes("box-a")
            proxy.read_request_body(headers(Content_Length=60), io.BytesIO(b"a" * 60), first)
            refused = proxy.reserve_body_bytes("box-a")
            unread = Mock()
            with self.assertRaises(proxy.RequestBodyError) as caught:
                proxy.read_request_body(headers(Content_Length=41), unread, refused)
            self.assertEqual(caught.exception.status, 503)
            unread.read.assert_not_called()

            other = proxy.reserve_body_bytes("box-b")
            proxy.read_request_body(headers(Content_Length=100), io.BytesIO(b"b" * 100), other)
            self.assertEqual(proxy._BUFFERED_BODY_BYTES, 160)
            self.assertEqual(proxy._BOX_BUFFERED_BODY_BYTES, {"box-a": 60, "box-b": 100})
            proxy.release_body_bytes(other)
            proxy.release_body_bytes(refused)
            proxy.release_body_bytes(first)
            self.assertEqual(proxy._BUFFERED_BODY_BYTES, 0)
            self.assertEqual(proxy._BOX_BUFFERED_BODY_BYTES, {})

    def test_invalid_framing_keeps_its_status_when_body_budget_is_full(self):
        with patch.object(proxy, "MAX_BUFFERED_BODY_BYTES", 300), \
             patch.object(proxy, "MAX_BUFFERED_BODY_BYTES_PER_BOX", 100), \
             patch.object(proxy, "_BUFFERED_BODY_BYTES", 0), \
             patch.object(proxy, "_BOX_BUFFERED_BODY_BYTES", {}):
            occupied = [proxy.reserve_body_bytes(f"box-{index}") for index in range(3)]
            for reservation in occupied:
                reservation.resize(100)
            for framed, status in (
                (headers(Transfer_Encoding="gzip, chunked"), 501),
                (headers(Transfer_Encoding="chunked", Content_Length=1), 400),
            ):
                with self.assertRaises(proxy.RequestBodyError) as caught:
                    proxy.read_request_body(framed, io.BytesIO(), proxy.reserve_body_bytes("other"))
                self.assertEqual(caught.exception.status, status)
            self.assertEqual(proxy._BUFFERED_BODY_BYTES, 300)
            for reservation in occupied:
                proxy.release_body_bytes(reservation)

    def test_anonymous_requests_share_the_per_box_body_budget(self):
        with patch.object(proxy, "MAX_BUFFERED_BODY_BYTES", 300), \
             patch.object(proxy, "MAX_BUFFERED_BODY_BYTES_PER_BOX", 100), \
             patch.object(proxy, "_BUFFERED_BODY_BYTES", 0), \
             patch.object(proxy, "_BOX_BUFFERED_BODY_BYTES", {}):
            first = proxy.reserve_body_bytes()
            first.resize(60)
            refused = proxy.reserve_body_bytes()
            with self.assertRaises(proxy.RequestBodyError) as caught:
                refused.resize(41)
            self.assertEqual(caught.exception.status, 503)

            authenticated = proxy.reserve_body_bytes("box-a")
            authenticated.resize(100)
            self.assertEqual(proxy._BOX_BUFFERED_BODY_BYTES, {None: 60, "box-a": 100})
            proxy.release_body_bytes(authenticated)
            proxy.release_body_bytes(refused)
            proxy.release_body_bytes(first)
            self.assertEqual(proxy._BUFFERED_BODY_BYTES, 0)
            self.assertEqual(proxy._BOX_BUFFERED_BODY_BYTES, {})

    def test_request_cleanup_releases_body_and_box_on_exception(self):
        handler = proxy.Handler.__new__(proxy.Handler)
        handler._deadline = Mock()

        def fail_request(_handler):
            _handler._body_reservation = proxy.reserve_body_bytes("fixture-box")
            _handler._body_reservation.resize(20)
            _handler._admitted_box = "fixture-box"
            raise ValueError("fixture")

        with patch.object(proxy, "_BUFFERED_BODY_BYTES", 0), \
             patch.object(proxy, "_BOX_BUFFERED_BODY_BYTES", {}), \
             patch.object(proxy, "_BOX_REQUESTS", {"fixture-box": 1}), \
             patch.object(proxy.BaseHTTPRequestHandler, "handle_one_request", fail_request):
            with self.assertRaises(ValueError):
                handler.handle_one_request()
            self.assertEqual(proxy._BUFFERED_BODY_BYTES, 0)
            self.assertEqual(proxy._BOX_BUFFERED_BODY_BYTES, {})
            self.assertEqual(proxy._BOX_REQUESTS, {})

    def test_per_box_quota_refuses_without_incrementing(self):
        handler = proxy.Handler.__new__(proxy.Handler)
        handler.send_error = Mock()
        with patch.object(proxy, "MAX_REQUESTS_PER_BOX", 1), \
             patch.object(proxy, "_BOX_REQUESTS", {"fixture-box": 1}):
            self.assertFalse(handler._admit_box("fixture-box"))
            handler.send_error.assert_called_once_with(503, "proxy per-box request budget exhausted")
            self.assertEqual(proxy._BOX_REQUESTS, {"fixture-box": 1})

    def test_tunnels_use_their_own_per_box_budget(self):
        handler = proxy.Handler.__new__(proxy.Handler)
        handler.send_error = Mock()
        with patch.object(proxy, "MAX_REQUESTS_PER_BOX", 1), \
             patch.object(proxy, "MAX_TUNNELS_PER_BOX", 2), \
             patch.object(proxy, "_BOX_REQUESTS", {"fixture-box": 1}), \
             patch.object(proxy, "_BOX_TUNNELS", {}):
            # A box at its request limit can still open tunnels, up to their own cap.
            self.assertTrue(handler._admit_box("fixture-box", tunnel=True))
            self.assertTrue(handler._admit_box("fixture-box", tunnel=True))
            self.assertFalse(handler._admit_box("fixture-box", tunnel=True))
            handler.send_error.assert_called_once_with(503, "proxy per-box tunnel budget exhausted")
            self.assertEqual(proxy._BOX_TUNNELS, {"fixture-box": 2})
            self.assertEqual(proxy._BOX_REQUESTS, {"fixture-box": 1})

    def test_loopback_source_cap_defaults_to_the_global_cap(self):
        # Every guest connects from 127.0.0.1; a smaller per-source default would
        # let one guest exhaust admission for all boxes before authentication.
        self.assertEqual(proxy.MAX_WORKERS_PER_SOURCE, proxy.MAX_WORKERS)

    def test_header_deadline_applies_to_stalled_local_fixture(self):
        with patch.object(proxy, "HEADER_TIMEOUT_SECONDS", 1), \
             patch.object(proxy.Handler, "log_message"):
            server = proxy.BoundedHTTPServer(("127.0.0.1", 0), proxy.Handler)
            worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
            worker.start()
            try:
                with socket.create_connection(server.server_address, timeout=2) as client:
                    client.sendall(b"GET /_devbox HTTP/1.1\r\nHost: fixture\r\n")
                    client.settimeout(2)
                    self.assertEqual(client.recv(1), b"")
            finally:
                server.shutdown()
                server.server_close()
                worker.join(2)

    def test_deadline_shutdown_uses_replaced_tls_socket(self):
        server = proxy.BoundedHTTPServer.__new__(proxy.BoundedHTTPServer)
        server._admission_lock = threading.Lock()
        original, wrapped = Mock(), Mock()
        server._connections = {original: ("fixture", 5, 20)}
        server._deadline_sockets = {original: wrapped}
        with patch.object(proxy.time, "monotonic", return_value=6):
            server.service_actions()
        wrapped.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        original.shutdown.assert_not_called()

    def test_relay_exits_on_idle_lifetime_and_capability_revocation(self):
        for idle, lifetime, authorize in ((1, 30, None), (30, 1, None), (30, 30, lambda: False)):
            handler = proxy.Handler.__new__(proxy.Handler)
            handler.connection = Mock()
            handler._deadline = Mock()
            upstream = Mock()
            with patch.object(proxy, "STREAM_IDLE_TIMEOUT_SECONDS", idle), \
                 patch.object(proxy, "MAX_CONNECTION_SECONDS", lifetime), \
                 patch.object(proxy.time, "monotonic", side_effect=[0, 2]), \
                 patch.object(proxy.select, "select") as select_call:
                self.assertEqual(handler._relay_socket(upstream, authorize), (0, 0))
            select_call.assert_not_called()
            upstream.close.assert_called_once()
            self.assertTrue(handler.close_connection)

    def test_relay_backpressure_cannot_delay_revocation(self):
        handler = proxy.Handler.__new__(proxy.Handler)
        handler.connection = Mock()
        handler.connection.recv.return_value = b"fixture"
        handler._deadline = Mock()
        upstream = Mock()
        upstream.send.side_effect = BlockingIOError()
        authorize = Mock(side_effect=[True, True, False])
        with patch.object(proxy.time, "monotonic", return_value=0), \
             patch.object(proxy.select, "select", side_effect=[([handler.connection], [], []), ([], [upstream], [])]):
            self.assertEqual(handler._relay_socket(upstream, authorize), (7, 0))
        upstream.sendall.assert_not_called()
        self.assertEqual(authorize.call_count, 3)
        upstream.close.assert_called_once()

    def test_relay_delivers_each_direction_without_blocking_sendall(self):
        client, incoming = socket.socketpair()
        outgoing, remote = socket.socketpair()
        handler = proxy.Handler.__new__(proxy.Handler)
        handler.connection = incoming
        handler._deadline = Mock()
        revoked = threading.Event()
        result = []
        worker = threading.Thread(target=lambda: result.append(handler._relay_socket(outgoing, lambda: not revoked.is_set())), daemon=True)
        worker.start()
        try:
            client.settimeout(2)
            remote.settimeout(2)
            client.sendall(b"request")
            self.assertEqual(remote.recv(7), b"request")
            remote.sendall(b"response")
            self.assertEqual(client.recv(8), b"response")
            revoked.set()
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(result, [(7, 8)])
        finally:
            revoked.set()
            for connection in (client, incoming, outgoing, remote):
                connection.close()
            worker.join(2)


class AuditLimitsTests(TestCase):
    def test_rotations_bound_all_retained_bytes_and_preserve_recent_records(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(proxy, "AUDIT_PATH", str(Path(directory) / "audit.jsonl")), \
             patch.object(proxy, "AUDIT_MAX_FILE_BYTES", 160), \
             patch.object(proxy, "AUDIT_BACKUP_COUNT", 2), \
             patch.object(proxy, "AUDIT_MIN_FREE_BYTES", 0), \
             patch.object(proxy, "AUDIT_ENABLED", True):
            # The first append moves a legacy oversized file aside, intact.
            legacy = ''.join(json.dumps({"old": i}) + "\n" for i in range(30))
            Path(proxy.AUDIT_PATH).write_text(legacy)
            for index in range(30):
                proxy.write_audit_event({"fixture": index})
                logs = list(Path(directory).glob("audit.jsonl*"))
                moved = [item for item in logs if ".legacy-" in item.name]
                self.assertEqual(len(moved), 1)
                self.assertEqual(moved[0].read_text(), legacy)
                logs = [item for item in logs if item.suffix != ".lock" and ".legacy-" not in item.name]
                self.assertLessEqual(sum(item.stat().st_size for item in logs), 160 * 3)
                self.assertTrue(all(item.stat().st_size <= 160 for item in logs))
                self.assertTrue(all(item.stat().st_mode & 0o777 == 0o600 for item in logs))
            self.assertEqual(proxy.read_audit_events()[-1], {"fixture": 29})

    def test_ai_traffic_cannot_rotate_out_github_and_traffic_records(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(proxy, "AUDIT_PATH", str(Path(directory) / "audit.jsonl")), \
             patch.object(proxy, "AUDIT_MAX_FILE_BYTES", 400), \
             patch.object(proxy, "AUDIT_BACKUP_COUNT", 1), \
             patch.object(proxy, "AUDIT_MIN_FREE_BYTES", 0), \
             patch.object(proxy, "AUDIT_ENABLED", True):
            evidence = {"source": "github-connect", "request": {"mutating": True}, "timestamp": "2026-01-01T00:00:00Z"}
            proxy.write_audit_event(evidence)
            for index in range(50):
                proxy.write_audit_event({"source": "auth-proxy", "timestamp": f"2026-01-01T00:00:{index:02d}Z",
                                         "request": {"body": {"text": "x" * 150}}})
            events = proxy.read_audit_events()
            self.assertIn(evidence, events)
            self.assertTrue(Path(proxy.audit_ai_path()).exists())

    def test_low_free_space_refuses_append_without_growing_log(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(proxy, "AUDIT_PATH", str(Path(directory) / "audit.jsonl")), \
             patch.object(proxy, "AUDIT_MIN_FREE_BYTES", 100), \
             patch.object(proxy, "AUDIT_ENABLED", True), \
             patch.object(proxy.shutil, "disk_usage", return_value=SimpleNamespace(free=100)):
            with self.assertRaisesRegex(OSError, "reserve"):
                proxy.write_audit_event({"fixture": True})
            self.assertFalse(Path(proxy.AUDIT_PATH).exists())

    def test_repeated_auth_failures_are_rate_bounded_and_counted(self):
        with patch.object(proxy, "_AUDIT_LAST_FAILURE", {}), \
             patch.object(proxy, "_AUDIT_LAST_GLOBAL_FAILURE", 0), \
             patch.object(proxy, "_AUDIT_DROPPED_FAILURES", 0), \
             patch.object(proxy.time, "monotonic", return_value=100), \
             patch.object(proxy, "write_audit_event") as write:
            for index in range(20):
                proxy.write_audit_failure({"client": "fixture"})
            self.assertEqual(write.call_count, 1)
            self.assertEqual(proxy._AUDIT_DROPPED_FAILURES, 19)
            with patch.object(proxy.time, "monotonic", return_value=111):
                proxy.write_audit_failure({"client": "fixture"})
            self.assertEqual(write.call_args.args[0]["suppressed_failures"], 19)

    def test_json_redacts_credential_spelling_variants_recursively(self):
        keys = ["accessToken", "refreshToken", "clientSecret", "apiKey", "APIKey", "Access-Token", "access_token"]
        body = json.dumps({"nested": [{key: "synthetic-secret" for key in keys}], "prompt": "fixture"}).encode()
        captured = proxy.audit_body(body, "application/json")
        self.assertNotIn("synthetic-secret", json.dumps(captured))
        self.assertEqual(captured["json"]["prompt"], "fixture")
        with patch.object(proxy, "AUDIT_MAX_BODY_BYTES", 20):
            truncated = proxy.audit_body(body, "application/json")
        self.assertTrue(truncated["truncated"])
        self.assertNotIn("text", truncated)

    def test_graphql_classification_does_not_parse_oversized_payload(self):
        body = b'{"query":"mutation { update }","fixture":"large"}'
        with patch.object(proxy, "AUDIT_MAX_BODY_BYTES", 20), \
             patch.object(proxy.json, "loads") as parse:
            self.assertEqual(proxy.audit_action("POST", "/graphql", body), ("graphql-operation", True))
        parse.assert_not_called()

    def test_audit_append_fsyncs_content_and_directory(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(proxy, "AUDIT_PATH", str(Path(directory) / "audit.jsonl")), \
             patch.object(proxy, "AUDIT_ENABLED", True), \
             patch.object(proxy, "AUDIT_MIN_FREE_BYTES", 0), \
             patch.object(proxy.os, "fsync") as sync:
            proxy.write_audit_event({"fixture": True})
            self.assertEqual(sync.call_count, 2)


class DiagnosticLimitsTests(TestCase):
    class RawRequest:
        """Feed request-line bytes through BaseHTTPRequestHandler without a listener."""
        def __init__(self, payload):
            self.reader = io.BytesIO(payload)
            self.response = bytearray()

        def makefile(self, mode, buffering=None):
            if mode != "rb":
                raise AssertionError(f"unexpected stream mode: {mode}")
            return self.reader

        def sendall(self, data):
            self.response.extend(data)

        def settimeout(self, _seconds):
            pass

        def close(self):
            pass

    def test_raw_request_diagnostics_escape_controls_and_omit_query_values(self):
        request = self.RawRequest(
            b"GET /visible\x1b[2J\x07\x7f\x9b?token=synthetic-secret HTTP/1.1\r\n"
            b"Host: fixture\r\nConnection: close\r\n\r\n"
        )
        log = io.StringIO()
        with patch.object(proxy.sys, "stderr", log), patch.object(proxy, "ROUTES", []):
            proxy.Handler(request, ("fixture", 123), SimpleNamespace())

        diagnostics = log.getvalue()
        self.assertEqual(bytes(request.response).split(b"\r\n", 1)[0], b"HTTP/1.1 404 no matching route")
        self.assertNotIn("synthetic-secret", diagnostics)
        self.assertNotIn("\x1b", diagnostics)
        self.assertNotIn("\x07", diagnostics)
        self.assertNotIn("\x7f", diagnostics)
        self.assertNotIn("\x9b", diagnostics)
        self.assertIn(r"GET /visible\u001b[2J\u0007\u007f\u009b", diagnostics)

    def test_diagnostic_encoder_covers_control_and_bidi_classes(self):
        codepoints = (
            list(range(0x20)) + [0x7f] + list(range(0x80, 0xa0))
            + [0x061c, 0x200e, 0x200f, *range(0x202a, 0x202f), *range(0x2066, 0x206a)]
        )
        rendered = proxy.terminal_safe_diagnostic("".join(map(chr, codepoints)))
        for codepoint in codepoints:
            self.assertNotIn(chr(codepoint), rendered)
            self.assertIn(f"\\u{codepoint:04x}", rendered)

    def test_diagnostics_escape_bidi_controls_and_preserve_ordinary_fields(self):
        handler = proxy.Handler.__new__(proxy.Handler)
        handler.command = "G\x1b\u202eET"
        handler.path = "/ordinary/path\u2066?mode=detail"
        log = io.StringIO()
        with patch.object(proxy.sys, "stderr", log):
            handler.log_message("ignored")

        self.assertEqual(
            log.getvalue(),
            r"[devbox-ai-proxy] G\u001b\u202eET /ordinary/path\u2066" + "\n",
        )

    def test_audit_show_is_terminal_safe_and_remains_json(self):
        event = {
            "client": "żółw",
            "body": "tag:\U000e0001:end",
            "request": {
                "method": "G\x9bET\u202e",
                "path": "/v1/test\x9b\u2066",
                "query_keys": ["q\x9b"],
            },
        }
        output = io.StringIO()
        with patch.object(proxy.sys, "argv", ["devbox-ai-proxy", "--audit-show"]), \
             patch.object(proxy.sys, "stdout", output), \
             patch.object(proxy, "read_audit_events", return_value=[event]):
            proxy.main()

        rendered = output.getvalue()
        self.assertNotIn("\x9b", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertNotIn("\u2066", rendered)
        self.assertNotIn("\U000e0001", rendered)
        self.assertIn(r"G\u009bET\u202e", rendered)
        self.assertIn(r"tag:\udb40\udc01:end", rendered)
        self.assertEqual(json.loads(rendered), event)

    def test_redirected_regular_file_stays_within_quota(self):
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as log:
            bounded = proxy.BoundedDiagnosticStream(log, 64)
            for _ in range(20):
                bounded.write("fixture diagnostic\n")
                self.assertLessEqual(os.fstat(log.fileno()).st_size, 64)
            bounded.write("ł" * 1000)
            self.assertLessEqual(os.fstat(log.fileno()).st_size, 64)
            self.assertGreater(bounded.truncations, 0)
            log.seek(0)
            self.assertEqual(log.read(), "ł" * 32)

    def test_existing_oversized_log_is_bounded_on_next_write(self):
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as log:
            log.write("old" * 100)
            log.flush()
            bounded = proxy.BoundedDiagnosticStream(log, 64)
            bounded.write("new fixture\n")
            log.seek(0)
            self.assertEqual(log.read(), "new fixture\n")

    def test_pipe_output_retains_normal_behavior(self):
        read_fd, write_fd = os.pipe()
        try:
            with os.fdopen(write_fd, "w", encoding="utf-8") as writer:
                bounded = proxy.BoundedDiagnosticStream(writer, 4)
                bounded.writelines(["fixture one\n", "fixture two\n"])
            self.assertEqual(os.read(read_fd, 100), b"fixture one\nfixture two\n")
        finally:
            os.close(read_fd)


class TrafficAuditTests(TestCase):
    def handler(self, target):
        handler = proxy.Handler.__new__(proxy.Handler)
        handler.headers = headers()
        handler.command, handler.path = "GET", target
        handler.client_address = ("fixture", 123)
        handler._read_body = Mock(return_value=None)
        handler._admit_box = Mock(return_value=True)
        handler.send_error = Mock()
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.wfile = io.BytesIO()
        return handler

    def test_ipv6_audit_and_host_authority_are_correct_before_forwarding(self):
        handler = self.handler("http://[2001:4860:4860::8888]/fixture")
        events = []
        connection = Mock()
        response = Mock(status=202, reason="Accepted")
        response.getheaders.return_value = []
        response.read1.side_effect = [b"fixture", b""]
        connection.getresponse.return_value = response

        def connect(_host, _port):
            self.assertEqual(events[0]["phase"], "request-open")
            return Mock()

        with patch.object(proxy, "traffic_proxy_authorized", return_value=True), \
             patch.object(proxy, "traffic_request_box", return_value="fixture-box"), \
             patch.object(proxy, "AUDIT_ENABLED", True), \
             patch.object(proxy, "write_audit_event", side_effect=events.append), \
             patch.object(proxy, "open_traffic_connection", side_effect=connect), \
             patch.object(proxy.http.client, "HTTPConnection", return_value=connection):
            handler._traffic_http_proxy("2001:4860:4860::8888", 80, "/fixture")
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["upstream"], {"scheme": "http", "host": "2001:4860:4860::8888", "port": 80})
        self.assertEqual(events[0]["request_id"], events[1]["request_id"])
        self.assertEqual(events[1]["response"]["status"], 202)
        connection.putheader.assert_any_call("Host", "[2001:4860:4860::8888]")

    def test_audit_disabled_or_failed_prevents_any_traffic_connection(self):
        for enabled in (False, True):
            handler = self.handler("http://fixture.example/fixture")
            with patch.object(proxy, "traffic_proxy_authorized", return_value=True), \
                 patch.object(proxy, "traffic_request_box", return_value="fixture-box"), \
                 patch.object(proxy, "AUDIT_ENABLED", enabled), \
                 patch.object(proxy, "write_audit_event", side_effect=OSError("fixture unavailable")), \
                 patch.object(proxy, "open_traffic_connection") as connect:
                handler._traffic_http_proxy("fixture.example", 80, "/fixture")
            connect.assert_not_called()
            handler.send_error.assert_called_once_with(503, "proxy audit storage unavailable")

    def test_constructing_bad_audit_metadata_prevents_forwarding(self):
        handler = self.handler("http://fixture.example/fixture")
        with patch.object(proxy, "traffic_proxy_authorized", return_value=True), \
             patch.object(proxy, "traffic_request_box", return_value="fixture-box"), \
             patch.object(proxy, "AUDIT_ENABLED", True), \
             patch.object(proxy, "build_audit_event", side_effect=ValueError("fixture metadata")), \
             patch.object(proxy, "open_traffic_connection") as connect:
            handler._traffic_http_proxy("fixture.example", 80, "/fixture")
        connect.assert_not_called()
        handler.send_error.assert_called_once_with(503, "proxy audit storage unavailable")

    def test_connect_handshake_disconnect_closes_opened_upstream(self):
        # Exercise both newly opened raw-socket branches, before relay starts.
        for traffic in (True, False):
            for fail_at in ("send_response", "end_headers"):
                with self.subTest(traffic=traffic, fail_at=fail_at):
                    handler = self.handler("fixture.example:443")
                    handler.command = "CONNECT"
                    handler.connection = Mock()
                    handler._deadline = Mock()
                    handler._audit_before_forwarding = Mock(return_value=True)
                    handler._relay_socket = Mock()
                    getattr(handler, fail_at).side_effect = BrokenPipeError("synthetic disconnect")
                    upstream = Mock()
                    with patch.object(proxy, "traffic_connect_target", return_value=("fixture.example", 443)), \
                         patch.object(proxy, "traffic_request_box", return_value="fixture-box" if traffic else None), \
                         patch.object(proxy, "github_connect_target", return_value=("tunnel", "github.com")), \
                         patch.object(proxy, "github_request_box", return_value="fixture-box"), \
                         patch.object(proxy, "open_traffic_connection", return_value=upstream), \
                         patch.object(proxy.socket, "create_connection", return_value=upstream):
                        with self.assertRaises(BrokenPipeError):
                            handler._connect()
                    upstream.close.assert_called_once()
                    handler._relay_socket.assert_not_called()


class CapabilityKeyTests(TestCase):
    def test_key_is_created_owner_only_and_reread(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(proxy, "STATE_DIR", directory):
            path = str(Path(directory) / "key")
            key = proxy._load_or_create_capability_key(path, ".k-")
            self.assertEqual(len(key), 32)
            self.assertEqual(Path(path).stat().st_mode & 0o777, 0o600)
            self.assertEqual(proxy._load_or_create_capability_key(path, ".k-"), key)
            self.assertEqual([p.name for p in Path(directory).iterdir()], ["key"])

    def test_unreadable_or_truncated_key_fails_closed_instead_of_rotating(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(proxy, "STATE_DIR", directory):
            path = Path(directory) / "key"
            path.write_bytes(b"short")
            path.chmod(0o600)
            with self.assertRaises(OSError):
                proxy._load_or_create_capability_key(str(path), ".k-")
            self.assertEqual(path.read_bytes(), b"short")
            path.write_bytes(b"k" * 32)
            path.chmod(0o644)
            with self.assertRaises(OSError):
                proxy._load_or_create_capability_key(str(path), ".k-")
            self.assertEqual(path.read_bytes(), b"k" * 32)
