from __future__ import annotations

import json
import multiprocessing
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from trust_triage.deep_analysis.llm_interpreter import (
    MonoGPTClaudeInterpreter,
    MonoGPTConfig,
)
from trust_triage.deep_analysis.models import LLMInterpretationStatus


def _response_body() -> bytes:
    content = json.dumps(
        {
            "verdict": "UNKNOWN",
            "confidence": 0.1,
            "supporting_evidence_ids": [],
            "contradicting_evidence_ids": [],
            "attack_techniques": [],
            "summary": "bounded fixture response",
            "manual_review_required": True,
        }
    )
    return json.dumps({"choices": [{"message": {"content": content}}]}).encode()


@pytest.fixture
def llm_server():
    modes: queue.Queue[str] = queue.Queue()
    response_body = _response_body()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            mode = modes.get(timeout=2)
            if mode == "large":
                body = b"x" * 4096
            else:
                body = response_body
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                if mode == "slow":
                    for byte in body:
                        self.wfile.write(bytes((byte,)))
                        self.wfile.flush()
                        time.sleep(0.05)
                else:
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, modes
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _interpreter(server, *, timeout=0.25, max_response_bytes=1024):
    return MonoGPTClaudeInterpreter(
        MonoGPTConfig(
            api_key="fixture-key",
            base_url=f"http://127.0.0.1:{server.server_port}",
            model="fixture-model",
            timeout_seconds=timeout,
            max_response_bytes=max_response_bytes,
        )
    )


def test_slow_trickle_obeys_total_deadline_and_releases_request_process(llm_server):
    server, modes = llm_server
    interpreter = _interpreter(server)
    before = {child.pid for child in multiprocessing.active_children()}
    modes.put("slow")

    started = time.monotonic()
    timed_out = interpreter.interpret((), sha256="a" * 64)
    elapsed = time.monotonic() - started

    assert timed_out.status is LLMInterpretationStatus.TIMEOUT
    assert elapsed < 0.7
    assert {child.pid for child in multiprocessing.active_children()} <= before

    modes.put("fast")
    recovered = interpreter.interpret((), sha256="a" * 64)
    assert recovered.status is LLMInterpretationStatus.SUCCESS


def test_response_size_limit_rejects_body_and_next_request_still_runs(llm_server):
    server, modes = llm_server
    interpreter = _interpreter(server, timeout=1.5, max_response_bytes=512)
    modes.put("large")

    oversized = interpreter.interpret((), sha256="a" * 64)

    assert oversized.status is LLMInterpretationStatus.INVALID_RESPONSE
    assert "size limit" in oversized.error
    modes.put("fast")
    recovered = interpreter.interpret((), sha256="a" * 64)
    assert recovered.status is LLMInterpretationStatus.SUCCESS
