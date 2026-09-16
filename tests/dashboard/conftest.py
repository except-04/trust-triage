"""dashboard/app.py 를 Streamlit 런타임 없이 불러오기 위한 준비.

app.py 는 스크립트라서 import 하는 순간 화면 렌더 코드까지 실행된다. 실제
Streamlit 런타임을 띄우는 대신, 위젯/레이아웃 호출을 받아 넘기는 최소 스텁을
sys.modules 에 끼워 넣고 import 한 뒤 원래 상태로 되돌린다. app 모듈은 스텁을
계속 참조하므로 테스트에서 st.session_state 를 그대로 들여다볼 수 있다.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types
from pathlib import Path

import pytest


DASHBOARD_DIR = Path(__file__).parents[2] / "dashboard"

# app.py 가 `import api_client` 로 형제 모듈을 부른다. 테스트 모듈도 ApiError 를
# 같은 경로에서 가져와야 app 쪽 except 절과 같은 클래스가 된다.
if str(DASHBOARD_DIR) not in sys.path:
    sys.path.append(str(DASHBOARD_DIR))


class SessionState(dict):
    """st.session_state 대역. 속성 접근과 dict 접근을 모두 받는다."""

    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError as e:
            raise AttributeError(key) from e

    def __setattr__(self, key, value):
        self[key] = value

    def __delattr__(self, key):
        del self[key]


class Rerun(Exception):
    """st.rerun() 호출을 테스트에서 관측하기 위한 신호."""


class Stop(Exception):
    """st.stop() 호출을 테스트에서 관측하기 위한 신호."""


class Element:
    """st 및 컨테이너 대역.

    위젯 호출은 전부 삼키고 None(=falsy)을 돌려준다. 레이아웃 함수만 다시
    Element 를 돌려줘서 `panel.markdown(...)` 같은 연쇄 호출이 성립한다.
    """

    _LAYOUT = ("container", "expander", "empty", "form", "popover", "status")

    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        def record(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            if name in self._LAYOUT:
                return Element()
            if name in ("columns", "tabs"):
                spec = args[0] if args else 1
                count = spec if isinstance(spec, int) else len(spec)
                return [Element() for _ in range(count)]
            return None

        return record

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _streamlit_stub():
    module = types.ModuleType("streamlit")
    element = Element()

    # 위젯/레이아웃 호출은 Element 가 모두 받는다
    module.__getattr__ = element.__getattr__
    module.session_state = SessionState()

    def fragment(*args, **kwargs):
        # @st.fragment 와 @st.fragment(run_every=...) 두 형태를 모두 받는다
        if args and callable(args[0]):
            return args[0]
        return lambda fn: fn

    def rerun(*args, **kwargs):
        raise Rerun()

    def stop(*args, **kwargs):
        raise Stop()

    module.fragment = fragment
    module.rerun = rerun
    module.stop = stop
    module.set_page_config = lambda *a, **k: None
    module.markdown = lambda *a, **k: None
    return module


def _load_app():
    os.environ.setdefault("MPLBACKEND", "Agg")
    saved_streamlit = sys.modules.get("streamlit")
    sys.modules["streamlit"] = _streamlit_stub()
    try:
        spec = importlib.util.spec_from_file_location(
            "dashboard_app_under_test", DASHBOARD_DIR / "app.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        if saved_streamlit is None:
            sys.modules.pop("streamlit", None)
        else:
            sys.modules["streamlit"] = saved_streamlit
    return module


_APP = None


@pytest.fixture
def app():
    """app 모듈. session_state 는 테스트마다 비워서 넘긴다."""
    global _APP
    if _APP is None:
        _APP = _load_app()
    _APP.st.session_state.clear()
    _APP.st.session_state.analysis_result = None
    _APP.st.session_state.batch_results = []
    return _APP


@pytest.fixture
def rerun_signal():
    return Rerun
