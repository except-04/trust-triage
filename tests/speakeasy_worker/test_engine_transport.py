"""PE나 에뮬레이터 없이 일반 자식 프로세스로 결과 전송과 종료를 검증한다."""

import multiprocessing
import queue
import time

import pytest

from trust_triage.dynamic_analysis.speakeasy_analyzer import (
    _close_queue,
    _receive_worker_message,
)


def _send_large_message(output):
    output.put("harmless report data " * 100_000)


def _no_message(output):
    return


def _sleep_instead_of_sending(output):
    time.sleep(10)


@pytest.mark.parametrize(
    "target,expected",
    [
        (_send_large_message, None),
        (_no_message, queue.Empty),
        (_sleep_instead_of_sending, TimeoutError),
    ],
)
def test_result_pipe_handles_large_output_exit_and_timeout(target, expected):
    context = multiprocessing.get_context("spawn")
    output = context.Queue(maxsize=1)
    process = context.Process(target=target, args=(output,))
    process.start()
    try:
        if expected is None:
            message = _receive_worker_message(process, output, 5)
            assert message == "harmless report data " * 100_000
            assert not process.is_alive()
        else:
            with pytest.raises(expected):
                _receive_worker_message(process, output, 1)
    finally:
        if process.is_alive():
            process.terminate()
        process.join(2)
        if process.is_alive():
            process.kill()
            process.join(2)
        _close_queue(output)
