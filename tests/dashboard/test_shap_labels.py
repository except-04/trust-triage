"""SHAP 차트 라벨: display_name 우선, 없으면 raw feature_name.

display_name 은 백엔드가 덧붙이는 선택 필드다. 이 필드가 생기기 전 기록, 목업,
라벨을 붙이지 못한 특성(raw 이름과 동일)이 모두 같은 화면을 지나가므로 세 경우가
전부 깨지지 않아야 한다.
"""

from __future__ import annotations

import pytest


def feature(name, label=None, value=0.3):
    item = {
        "feature_name": name,
        "feature_value": 1.0,
        "shap_value": value,
        "direction": "MALICIOUS" if value >= 0 else "BENIGN",
    }
    if label is not None:
        item["display_name"] = label
    return item


@pytest.mark.parametrize(
    "item,expected",
    [
        (feature("header[9]", "Major Linker Version"), "Major Linker Version"),
        (feature("imports[300]", "Import API hash bucket #42"), "Import API hash bucket #42"),
        # 라벨을 못 붙이면 백엔드가 raw 이름을 그대로 넣는다
        (feature("f[2]", "f[2]"), "f[2]"),
        # 도입 이전 기록: 필드 자체가 없거나 null
        (feature("header[9]"), "header[9]"),
        ({**feature("header[9]"), "display_name": None}, "header[9]"),
        ({**feature("header[9]"), "display_name": ""}, "header[9]"),
        # 목업 키
        ({"feature": "legacy", "value": 0.1}, "legacy"),
        ({"SHAP 특성": "구형", "영향도": 0.1}, "구형"),
        ({}, "Unknown"),
    ],
)
def test_shap_feature_label_prefers_display_name(app, item, expected):
    assert app.shap_feature_label(item) == expected


def test_chart_uses_display_names_and_keeps_raw_names_untouched(app):
    class Target:
        figures = []

        def pyplot(self, figure, **kwargs):
            self.figures.append(figure)

    features = [
        feature("header[9]", "Major Linker Version", 0.4),
        feature("pefilewarnings[67]", "PE Warning: Suspicious flags set for section", 0.2),
        feature("section[3]", "Read/Execute Section Count", -0.1),
        feature("header[43]"),  # 라벨 없는 구형 기록이 섞여도 된다
    ]
    target = Target()
    app.render_shap_chart(target, features)

    assert len(target.figures) == 1
    labels = [tick.get_text() for tick in target.figures[0].axes[0].get_yticklabels()]
    assert labels == [
        "Major Linker Version",
        "PE Warning: Suspicious flags set for section",
        "Read/Execute Section Count",
        "header[43]",
    ]
    # 입력 dict 는 바꾸지 않는다 — feature_name 은 식별자로 남아야 한다
    assert [f["feature_name"] for f in features] == [
        "header[9]",
        "pefilewarnings[67]",
        "section[3]",
        "header[43]",
    ]
