# TRUST-Triage Interface Specification

> **臾몄꽌 紐⑹쟻**  
> TRUST-Triage ?쒕퉬?ㅼ쓽 媛?而댄룷?뚰듃媛 **?대뼡 ?곗씠?곕? 二쇨퀬諛쏆븘???섎뒗吏**瑜??뺤쓽?섎뒗 怨듯넻 ?명꽣?섏씠??紐낆꽭?쒖엯?덈떎.  
> Frontend, Backend, JRR, Deep Analysis, Task Queue/Worker, Database, MCP ?대떦?먭? ?숈씪???꾨뱶紐끒룹긽?쒓컪쨌?곗씠??援ъ“瑜??ъ슜?섎룄濡??섎뒗 寃껋쓣 紐⑺몴濡??⑸땲??

---

## 0. 臾몄꽌 ?곹깭

| ??ぉ | ?댁슜 |
|---|---|
| 臾몄꽌紐?| `TRUST-Triage Interface Specification` |
| 沅뚯옣 ?뚯씪紐?| `interface_spec.md` |
| ?곸슜 踰붿쐞 | M4 ?쒕퉬???듯빀 諛?諛깆뿏??援ъ텞 |
| 二쇱슂 ???| Frontend / Backend / DB / Deep Analysis / Task Queue / AWS / System Integration |
| ?곹깭 | Draft |
| 蹂寃??먯튃 | ?명꽣?섏씠???꾨뱶紐끒텲num쨌?꾩닔媛?蹂寃???? 怨듭쑀 ??臾몄꽌 ?곗꽑 ?섏젙 |

---

# ?슚 Critical ?ы빆

?꾨옒 ??ぉ? **紐⑤뱢 媛??명솚?깆쓣 ?꾪빐 諛섎뱶???숈씪?섍쾶 吏耳쒖빞 ?섎뒗 怨듯넻 怨꾩빟**?낅땲??

## CRITICAL-01. 怨듯넻 ?앸퀎???대쫫???듭씪?쒕떎

紐⑤뱺 ?쒕퉬?ㅼ뿉???꾨옒 ?꾨뱶紐낆쓣 ?숈씪?섍쾶 ?ъ슜?⑸땲??

- `analysis_id`: 媛쒕퀎 ?뚯씪 遺꾩꽍 1嫄댁쓽 怨좎쑀 ID
- `batch_id`: ?ㅼ쨷 ?뚯씪 遺꾩꽍 ?붿껌??怨좎쑀 ID
- `sha256`: 遺꾩꽍 ????뚯씪??SHA-256
- `created_at`: 遺꾩꽍 ?붿껌 ?앹꽦 ?쒓컖

> **Critical**  
> `id`, `job_id`, `sample_id` ???꾩쓽???대쫫?쇰줈 諛붽씀吏 ?딆뒿?덈떎.  
> 媛쒕퀎 遺꾩꽍??湲곗? ID??`analysis_id`濡??듭씪?⑸땲??

---

## CRITICAL-02. 遺꾩꽍 ?곹깭 Enum???듭씪?쒕떎

鍮꾨룞湲??묒뾽 諛?遺꾩꽍 吏꾪뻾 ?곹깭???꾨옒 媛믪쓣 ?ъ슜?⑸땲??

```text
QUEUED
RUNNING
COMPLETED
FAILED
NOT_REQUIRED
```

| ?곹깭 | ?섎? |
|---|---|
| `QUEUED` | ?묒뾽??Queue???깅줉?섏뼱 ?湲?以?|
| `RUNNING` | Worker ?먮뒗 遺꾩꽍 紐⑤뱢???ㅽ뻾 以?|
| `COMPLETED` | ?뺤긽?곸쑝濡?遺꾩꽍 ?꾨즺 |
| `FAILED` | 遺꾩꽍 ?ㅽ뙣 |
| `NOT_REQUIRED` | ?대떦 遺꾩꽍 ?④퀎媛 ?꾩슂?섏? ?딆븘 ?ㅽ뻾?섏? ?딆쓬 |

> **Critical**  
> Frontend, Backend, Worker, DB媛 ?쒕줈 ?ㅻⅨ ?곹깭 臾몄옄?댁쓣 ?ъ슜?섏? ?딆뒿?덈떎.

---

## CRITICAL-03. JRR Verdict 媛믪쓣 ?듭씪?쒕떎

珥덇린 JRR ?먯젙? ?꾨옒 3媛?媛믩쭔 ?ъ슜?⑸땲??

```text
AUTO_BENIGN
AUTO_MALICIOUS
HIGH_RISK_UNCERTAIN
```

> **Critical**  
> `HIGH_RISK`, `UNCERTAIN`, `REVIEW` ???좎궗 ?쒗쁽??蹂꾨룄 媛믪쑝濡?異붽??섏? ?딆뒿?덈떎.  
> UI ?쒖떆 臾멸뎄媛 ?꾩슂?섎㈃ Frontend?먯꽌 蹂꾨룄 Label濡?蹂?섑빀?덈떎.

---

## CRITICAL-04. Raw PE ?뚯씪 ?먯껜瑜?Queue 硫붿떆吏???ｌ? ?딅뒗??

Task Queue?먮뒗 PE 諛붿씠?덈━ ?먯껜瑜??꾨떖?섏? ?딄퀬 **?뚯씪 ?꾩튂瑜?李몄“?????덈뒗 ?앸퀎?먮쭔 ?꾨떖**?⑸땲??

??

```json
{
  "analysis_id": "a_20260907_000001",
  "sha256": "....",
  "file_location": "s3://trust-triage-temp/...."
}
```

> **Critical**  
> Raw PE??Queue 硫붿떆吏, DB JSON, 濡쒓렇 ?깆뿉 Base64 ?뺥깭濡?吏곸젒 ?쎌엯?섏? ?딆뒿?덈떎.

---

## CRITICAL-05. ?먯젙 ?④퀎???쒕줈 ??뼱?곗? ?딅뒗??

TRUST-Triage???먯젙???④퀎蹂꾨줈 遺꾨━?섏뿬 蹂댁〈?⑸땲??

```text
initial_verdict
    ??
final_verdict
    ??
analyst_final_verdict
```

| ?꾨뱶 | ?섎? |
|---|---|
| `initial_verdict` | JRR??珥덇린 ?먯젙 |
| `final_verdict` | ?ъ링遺꾩꽍 諛??먮룞??寃곌낵瑜?諛섏쁺??理쒖쥌 ?쒖뒪???먯젙 |
| `analyst_final_verdict` | 遺꾩꽍媛媛 理쒖쥌 寃?????뺤젙???먯젙 |

> **Critical**  
> ?ъ링遺꾩꽍 寃곌낵媛 ?섏솕?ㅺ퀬 `initial_verdict`瑜???뼱?곗? ?딆뒿?덈떎.

---

## CRITICAL-06. SHAP怨?Behavioral Evidence瑜?遺꾨━?쒕떎

- `top_features`: **紐⑤뜽????洹몃젃寃??덉륫?덈뒗吏** ?ㅻ챸?섎뒗 SHAP 湲곕컲 紐⑤뜽 洹쇨굅
- `evidence`: CAPA / FLOSS / Speakeasy ?깆뿉???뺣낫??**?됱쐞쨌遺꾩꽍 洹쇨굅**

> **Critical**  
> SHAP 寃곌낵? CAPA/Speakeasy Evidence瑜??섎굹??洹쇨굅 ?꾨뱶???욎뼱 ??ν븯吏 ?딆뒿?덈떎.

---

## CRITICAL-07. ?몃? LLM?먮뒗 Raw PE瑜?吏곸젒 ?꾨떖?섏? ?딅뒗??

LLM Analyst Assist?먮뒗 ?꾨옒泥섎읆 **?뺥삎?붾맂 遺꾩꽍 寃곌낵? 異붿텧???띿뒪???뺣낫**留??꾨떖?⑸땲??

- CAPA 寃곌낵
- FLOSS 異붿텧 臾몄옄??
- Speakeasy ?됱쐞 寃곌낵
- MITRE ATT&CK Evidence
- JRR / SHAP ?붿빟 ?뺣낫

> **Critical**  
> ?몃? LLM API??Raw PE 諛붿씠?덈━瑜?吏곸젒 ?꾩넚?섏? ?딆뒿?덈떎.

---

## CRITICAL-08. `file_location`? ?대? ?쒕퉬???꾩슜 ?꾨뱶濡??ъ슜?쒕떎

`file_location`? Backend, Worker, Storage 媛??뚯씪 李몄“瑜??꾪븳 ?대? 媛믪엯?덈떎.

> **Critical**  
> S3 URI ?먮뒗 ?대? 寃쎈줈瑜?Frontend / ?몃? REST Client / MCP ?묐떟??洹몃?濡??몄텧?섏? ?딆뒿?덈떎.

---

## CRITICAL-09. ?꾩껜 遺꾩꽍 ?곹깭? ?꾧뎄蹂??곹깭瑜?援щ텇?쒕떎

- `status`: 遺꾩꽍 1嫄??꾩껜??吏꾪뻾 ?곹깭
- `deep_analysis_status`: CAPA / FLOSS / Speakeasy ???꾧뎄蹂??곹깭

??

```json
{
  "status": "RUNNING",
  "deep_analysis_status": {
    "capa": "COMPLETED",
    "floss": "COMPLETED",
    "speakeasy": "QUEUED"
  }
}
```

> **Critical**  
> Speakeasy ?섎굹媛 `QUEUED`?쇨퀬 ?댁꽌 ?꾩껜 遺꾩꽍 媛앹껜???곹깭瑜??꾩쓽濡?媛숈? 媛믪쑝濡???뼱?곗? ?딆뒿?덈떎.

---

# 1. ?꾩껜 ?명꽣?섏씠???먮쫫

```text
[Streamlit Frontend]
        ??
        ??Raw PE / Batch Upload
        ??
[FastAPI Backend]
        ??
        ?쒋?? SHA-256 / analysis_id ?앹꽦
        ?쒋?? ?뚯씪 ?꾩떆 ???
        ??
        ??
[Initial Analysis Pipeline]
Feature Extraction
??LightGBM / XGBoost
??Calibration
??Risk Signals
??JRR
??SHAP
        ??
        ?쒋?? AUTO_BENIGN
        ?쒋?? AUTO_MALICIOUS
        ??
        ?붴?? HIGH_RISK_UNCERTAIN
                    ??
                    ??
             [Deep Analysis]
             CAPA + FLOSS
                    ??
                    ??
              [Task Queue]
                    ??
                    ??
           [Speakeasy Worker]
                    ??
                    ??
              [LLM Summary]
                    ??
                    ??
            [Final Assessment]

        ??PostgreSQL
        ??Temporary File Storage / S3

[Optional MCP Server]
        ??
        ?붴?? 湲곗〈 Backend/API 湲곕뒫 ?ъ궗??
```

---

# 2. 怨듯넻 ?곗씠??洹쒖튃

## 2.1 怨듯넻 ?꾨뱶

媛?ν븳 紐⑤뱺 遺꾩꽍 寃곌낵 媛앹껜???꾨옒 怨듯넻 ?꾨뱶瑜??ы븿?⑸땲??

```json
{
  "analysis_id": "a_20260907_000001",
  "batch_id": null,
  "sha256": "64-character-sha256",
  "created_at": "2026-09-07T14:30:00+09:00"
}
```

### ?꾨뱶 ?뺤쓽

| ?꾨뱶 | ???| ?꾩닔 | ?ㅻ챸 |
|---|---|---:|---|
| `analysis_id` | string | O | 媛쒕퀎 遺꾩꽍 怨좎쑀 ID |
| `batch_id` | string / null | O | Batch ?붿껌???꾨땲硫?`null` |
| `sha256` | string | O | 遺꾩꽍 ?뚯씪 SHA-256 |
| `created_at` | ISO 8601 datetime | O | 遺꾩꽍 ?붿껌 ?앹꽦 ?쒓컖 |

---

## 2.2 ?쒓컙 ?뺤떇

紐⑤뱺 ?쒓컙媛믪? **ISO 8601** ?뺤떇 ?ъ슜??沅뚯옣?⑸땲??

```text
2026-09-07T14:30:00+09:00
```

?쒕쾭 ?대? UTC ?ъ슜 ?щ???Backend/AWS 援ы쁽 ???뺤젙?섎릺, API ?묐떟 ?뺤떇? ?쇨??섍쾶 ?좎??⑸땲??

---

## 2.3 Null 泥섎━

遺꾩꽍?섏? ?딆? 媛믪? 鍮?臾몄옄??`""`) ???`null`???ъ슜?⑸땲??

??

```json
{
  "batch_id": null,
  "analyst_final_verdict": null
}
```

---

# 3. Raw PE Input Interface

## 3.1 Single File Upload

### ?낅젰

```text
POST /analyses
Content-Type: multipart/form-data
```

| ?꾨뱶 | ???| ?꾩닔 | ?ㅻ챸 |
|---|---|---:|---|
| `file` | binary | O | Raw PE ?뚯씪 |

### Backend ?앹꽦媛?

Backend???낅줈?????ㅼ쓬 媛믪쓣 ?앹꽦?⑸땲??

- `analysis_id`
- `sha256`
- `file_location`
- `created_at`

### 珥덇린 ?묐떟 ?덉떆

```json
{
  "analysis_id": "a_20260907_000001",
  "batch_id": null,
  "sha256": "....",
  "status": "RUNNING",
  "created_at": "2026-09-07T14:30:00+09:00"
}
```

---

## 3.2 Batch / Multiple File Upload

### ?낅젰

```text
POST /batches
Content-Type: multipart/form-data
```

```text
files = [sample1.exe, sample2.exe, sample3.exe]
```

### ?묐떟 ?덉떆

```json
{
  "batch_id": "b_20260907_000001",
  "total_count": 3,
  "analyses": [
    {
      "analysis_id": "a_001",
      "sha256": "...",
      "status": "QUEUED"
    },
    {
      "analysis_id": "a_002",
      "sha256": "...",
      "status": "QUEUED"
    },
    {
      "analysis_id": "a_003",
      "sha256": "...",
      "status": "QUEUED"
    }
  ]
}
```

> **Critical**  
> Batch ?꾩껜???섎굹??`analysis_id`瑜?遺?ы븯吏 ?딆뒿?덈떎.  
> **?뚯씪留덈떎 ?낅┰?곸씤 `analysis_id`瑜??앹꽦**?섍퀬, ?곸쐞 洹몃９ ?앸퀎?먮줈 `batch_id`瑜??ъ슜?⑸땲??

---

# 4. Initial Analysis / JRR Interface

## 4.1 Initial Triage Result

Initial Analysis Pipeline ?꾨즺 ??Backend媛 ??Β룹젣怨듯븯???쒖? 援ъ“?낅땲??

```json
{
  "analysis_id": "a_20260907_000001",
  "sha256": "...",
  "prediction": {
    "lgbm_raw_probability": 0.9123,
    "xgb_raw_probability": 0.6842,
    "calibrated_probability": 0.8871
  },
  "risk_signals": {
    "disagreement": 0.2281,
    "ood_score": -0.031,
    "difficulty_score": 6
  },
  "initial_verdict": "HIGH_RISK_UNCERTAIN",
  "route": "DEEP_ANALYSIS",
  "reason": "Uncertain Probability (0.8871)",
  "triggered_signals": ["UNCERTAIN_PROBABILITY"]
}
```

## 4.2 Prediction Fields

| ?꾨뱶 | ???| ?ㅻ챸 |
|---|---|---|
| `lgbm_raw_probability` | float | LightGBM ?먯떆 ?낆꽦 ?뺣쪧 |
| `xgb_raw_probability` | float | XGBoost ?먯떆 ?낆꽦 ?뺣쪧 |
| `calibrated_probability` | float | Isotonic Calibration ?곸슜 ?뺣쪧 |

## 4.3 Risk Signals

```json
{
  "disagreement": 0.2281,
  "ood_score": -0.031,
  "difficulty_score": 6
}
```

| ?꾨뱶 | ?ㅻ챸 |
|---|---|
| `disagreement` | `abs(LGBM - XGBoost)` |
| `ood_score` | Isolation Forest `decision_function` 寃곌낵 |
| `difficulty_score` | PEFormatWarnings 湲곕컲 遺꾩꽍 ?쒖씠???먯닔 |

### ?꾩옱 湲곗?媛?

| ??ぉ | ?꾩옱 媛?|
|---|---:|
| `tau_low` | `0.65` |
| `tau_high` | `0.983645` |
| `tau_disagree` | `0.30` |
| `tau_difficulty` | `6.0` |
| OOD 議곌굔 | `ood_score < 0` |

> `tau_low`? `tau_difficulty`??Calibration ?명듃(48留?嫄??먯꽌 `tau_low`횞`tau_difficulty` 2李⑥썝 Grid Search濡??숈떆 ?먯깋???뺤젙??媛믪엯?덈떎(?뺤쓽???꾨낫 grid? 紐⑹쟻?⑥닔 踰붿쐞 ??理쒖쟻 議고빀). ??媛믪씠 JRR??OR 議곌굔?먯꽌 ?쒕줈 ?곹샇?묒슜?섎?濡??쒖そ??怨좎젙??梨??쒖감?곸쑝濡?理쒖쟻?뷀븯吏 ?딆뒿?덈떎. Eval ?명듃?????먯깋???ъ슜?섏? ?딆븯?듬땲??
>
> Threshold 媛믪씠 蹂寃쎈맆 寃쎌슦 肄붾뱶留??섏젙?섏? 留먭퀬 愿???ㅺ퀎/?됯? 臾몄꽌? 蹂?紐낆꽭?쒕? ?④퍡 媛깆떊?⑸땲??

## 4.4 JRR Reason / Triggered Signals

JRR? **Priority-ordered Rule-based Router**?낅땲?? 媛??먯젙 ???꾨옒 ?쒖꽌濡??꾪뿕 ?좏샇瑜?寃?ы빀?덈떎.

```text
OOD
  ??Disagreement
    ??Difficulty
      ??Probability Gray Zone
        ??AUTO_MALICIOUS / AUTO_BENIGN
```

`reason`? ???곗꽑?쒖쐞??**媛??癒쇱? 留뚯”??洹쒖튃 1媛?*瑜?????ъ쑀濡?湲곕줉?⑸땲??

沅뚯옣 Reason Label:

```text
OOD Detected
High Model Disagreement
High Analysis Difficulty
Uncertain Probability
High Malicious Confidence
High Benign Confidence
```

> **Critical**  
> `Uncertain Probability`??蹂꾨룄???뺣쪧 ?꾨뱶媛 ?꾨떃?덈떎.  
> `tau_low < calibrated_probability < tau_high`??**Calibrated Probability Gray Zone**??????ㅻ챸??Reason Label?낅땲??  
> 怨듭떇 ?뺣쪧 ?꾨뱶紐낆? 怨꾩냽 `calibrated_probability`瑜??ъ슜?⑸땲??

`triggered_signals`??`reason`怨???븷???ㅻⅨ **蹂꾨룄??怨듭떇 諛섑솚 ?꾨뱶**?낅땲??`src/jrr/jrr_router.py::route_sample()`). OOD/Disagreement/Difficulty/Probability Gray Zone 4媛??좏샇??媛곴컖 ?낅┰?곸쑝濡?寃?щ릺硫? 議곌굔??留뚯”???뚮쭏???대떦 ?좏샇媛 `triggered_signals` 諛곗뿴??異붽??⑸땲????利????꾨뱶??**?숈떆??諛쒗쁽??紐⑤뱺 ?꾪뿕 ?좏샇**瑜?蹂댁〈?⑸땲??

媛?ν븳 媛?

```text
OOD
DISAGREEMENT
DIFFICULTY
UNCERTAIN_PROBABILITY
```

| ?꾨뱶 | ?섎? |
|---|---|
| `reason` | ?곗꽑?쒖쐞??理쒖큹濡?留ㅼ묶??????ъ쑀 1媛?(臾몄옄?? |
| `triggered_signals` | ?숈떆??諛쒗쁽??紐⑤뱺 ?꾪뿕 ?좏샇 (諛곗뿴, 寃???쒖꽌? ?숈씪?섍쾶 異붽??? |

????OOD쨌Disagreement쨌Difficulty媛 ?숈떆??諛쒗쁽??寃쎌슦, ???`reason`? 理쒖큹 留ㅼ묶??OOD ?섎굹留?湲곕줉?섏?留?`triggered_signals`?먮뒗 ?????⑥뒿?덈떎:

```json
{
  "initial_verdict": "HIGH_RISK_UNCERTAIN",
  "route": "DEEP_ANALYSIS",
  "reason": "OOD Detected (Score: -0.0310)",
  "triggered_signals": ["OOD", "DISAGREEMENT", "DIFFICULTY"]
}
```

> **Critical**  
> `AUTO_BENIGN` / `AUTO_MALICIOUS`泥섎읆 ?꾪뿕 ?좏샇媛 ?섎굹???녿뒗 寃쎌슦 `triggered_signals`??鍮?諛곗뿴 `[]`?낅땲??  
> `triggered_signals` ?꾩엯? ??Priority-ordered Routing ?쒖꽌?????`reason` ?곗텧 諛⑹떇??蹂寃쏀븯吏 ?딆뒿?덈떎 ???대뼡 ?좏샇媛 `AUTO_MALICIOUS`/`AUTO_BENIGN`???ㅼ쭛怨?`HIGH_RISK_UNCERTAIN`?쇰줈 寃⑹긽?쒗궎?붿????ъ쟾?????곗꽑?쒖쐞留뚯쑝濡?寃곗젙?⑸땲?? `triggered_signals`??洹?寃곌낵瑜?蹂댁“?곸쑝濡??곸꽭??湲곕줉?섎뒗 ?꾨뱶??肉먯엯?덈떎.

> **Critical ??`risk_score` 誘명룷??*  
> JRR 怨듭떇 output?먮뒗 `risk_score` ?꾨뱶媛 ?놁뒿?덈떎. JRR? ?щ윭 ?꾪뿕 ?좏샇瑜??섎굹??媛以묓빀(Weighted Risk Score)?쇰줈 ?⑹궛?섏? ?딄퀬, `reason` + `triggered_signals` + Priority-ordered Rule濡??쇱슦?낆쓣 寃곗젙?⑸땲?? "Joint"???щ윭 ?좏샇瑜??④퍡 怨좊젮?쒕떎???살씠硫?媛以??먯닔 ?곗텧???섎??섏? ?딆뒿?덈떎.

## 4.5 Fail-Closed Behavior

`p_calib`(`calibrated_probability`) / `disagreement` / `ood_score` / `difficulty_score` 以?**?섎굹?쇰룄 NaN?대㈃** 臾댁“嫄??꾨옒? 媛숈씠 諛섑솚?⑸땲??

```json
{
  "initial_verdict": "HIGH_RISK_UNCERTAIN",
  "route": "DEEP_ANALYSIS",
  "calibrated_probability": -1.0,
  "disagreement": -1.0,
  "ood_score": 0.0,
  "difficulty_score": 0.0,
  "reason": "System Error: NaN values detected (Fail-Closed)",
  "triggered_signals": []
}
```

> **Critical**  
> NaN ?낅젰?????`AUTO_BENIGN`/`AUTO_MALICIOUS`濡??먮룞 ?먯젙?섏? ?딆뒿?덈떎. ??긽 `HIGH_RISK_UNCERTAIN` + `route="DEEP_ANALYSIS"`濡?蹂대궡 ?ъ링遺꾩꽍쨌遺꾩꽍媛 寃?좊? 嫄곗튂?꾨줉 ?섎뒗 Fail-Closed ?뺤콉?낅땲??
>
> ??Fail-Closed ?묐떟???뺤긽 ?먯젙 寃쎈줈? ?숈씪??JRR output schema(`initial_verdict`/`route`/`calibrated_probability`/`disagreement`/`ood_score`/`difficulty_score`/`reason`/`triggered_signals`)瑜??좎??⑸땲?? `triggered_signals`?????먯껜媛 ?꾨씫?섎뒗 寃껋씠 ?꾨땲??**??긽 鍮?諛곗뿴 `[]`**??諛섑솚?⑸땲????System Error???꾪뿕 ?좏샇(risk signal)媛 ?꾨땲誘濡?`SYSTEM_ERROR` 媛숈? 蹂꾨룄 媛믪쓣 異붽??섏? ?딆쑝硫? ?ㅻ쪟 ?먯씤? `reason`?쇰줈留??쒗쁽?⑸땲??

## 4.6 Route

沅뚯옣 Route 媛?

```text
FINAL
DEEP_ANALYSIS
```

??

```json
{
  "initial_verdict": "AUTO_BENIGN",
  "route": "FINAL"
}
```

?먮뒗

```json
{
  "initial_verdict": "HIGH_RISK_UNCERTAIN",
  "route": "DEEP_ANALYSIS"
}
```

---

# 5. SHAP / XAI Interface

SHAP? **LightGBM 紐⑤뜽???먯젙 洹쇨굅**瑜??ㅻ챸?⑸땲??

```json
{
  "analysis_id": "a_20260907_000001",
  "top_features": [
    {
      "feature_name": "feature_102",
      "feature_value": 1.34,
      "shap_value": 0.281,
      "direction": "MALICIOUS"
    },
    {
      "feature_name": "feature_031",
      "feature_value": 0.22,
      "shap_value": -0.194,
      "direction": "BENIGN"
    }
  ]
}
```

> **Critical**  
> SHAP? **Raw LightGBM 異쒕젰?????紐⑤뜽 ?ㅻ챸**?낅땲??  
> `calibrated_probability`瑜?SHAP??吏곸젒 ?ㅻ챸?섎뒗 寃껋쿂???쒗쁽?섏? ?딆뒿?덈떎.

---

# 6. Deep Analysis Job Interface

`HIGH_RISK_UNCERTAIN` ?섑뵆? 癒쇱? **Tier 1(CAPA + FLOSS)** 遺꾩꽍???섑뻾?⑸땲??  
Tier 1 寃곌낵留뚯쑝濡?異⑸텇?섏? ?딆븘 Speakeasy媛 ?꾩슂??寃쎌슦?먮쭔 Tier 2 鍮꾨룞湲?Job??Queue???깅줉?⑸땲??

```text
HIGH_RISK_UNCERTAIN
        ??
CAPA + FLOSS
        ??
Speakeasy ?꾩슂
        ??
Task Queue
        ??
Speakeasy Worker
```

?꾩옱 Task Queue??**AWS SQS瑜??곗꽑 ?곸슜 ?꾨낫濡??먮ŉ, ? 理쒖쥌 ?뺤젙 ??蹂?臾몄꽌?먯꽌 TBD瑜??쒓굅?⑸땲??**

## 6.1 SQS Message Body

```json
{
  "analysis_id": "a_20260907_000001",
  "sha256": "...",
  "file_location": "s3://trust-triage-temp/sample.exe",
  "requested_stage": "SPEAKEASY",
  "requested_at": "2026-09-07T15:30:00+09:00"
}
```

| ?꾨뱶 | ?꾩닔 | ?ㅻ챸 |
|---|---:|---|
| `analysis_id` | O | 遺꾩꽍 ID |
| `sha256` | O | ?뚯씪 ?댁떆 |
| `file_location` | O | Worker媛 Raw PE瑜?媛?몄삱 ?꾩튂 |
| `requested_stage` | O | ?ㅽ뻾???ъ링遺꾩꽍 ?④퀎 (`SPEAKEASY`) |
| `requested_at` | O | Queue ?깅줉 ?쒓컖 |

> **Critical**  
> Queue 硫붿떆吏??媛?ν븳 ???묎쾶 ?좎??섍퀬, 遺꾩꽍 ?먮낯/???JSON ?꾩껜瑜?硫붿떆吏???ы븿?섏? ?딆뒿?덈떎.
>
> SQS Standard Queue ?ъ슜 ??以묐났 ?꾨떖 媛?μ꽦??怨좊젮?섏뿬 Worker??`analysis_id` 湲곗??쇰줈 **以묐났 ?꾨즺 泥섎━ 諛⑹?(Idempotency)** 濡쒖쭅??媛?몄빞 ?⑸땲??
>
> `file_location`? Worker???대? ?꾨뱶?대ŉ ?몃? API ?묐떟?먮뒗 ?몄텧?섏? ?딆뒿?덈떎.

---

# 7. CAPA Interface

```json
{
  "analysis_id": "a_20260907_000001",
  "tool": "CAPA",
  "status": "COMPLETED",
  "capabilities": [
    {
      "name": "example capability",
      "namespace": "example/namespace"
    }
  ],
  "mitre_techniques": [
    {
      "technique_id": "T1059",
      "technique_name": "Command and Scripting Interpreter"
    }
  ],
  "raw_result_location": null
}
```

---

# 8. FLOSS Interface

```json
{
  "analysis_id": "a_20260907_000001",
  "tool": "FLOSS",
  "status": "COMPLETED",
  "strings": {
    "static": [],
    "stack": [],
    "tight": [],
    "decoded": []
  }
}
```

> FLOSS 臾몄옄???먯껜瑜?怨㏓컮濡??낆꽦 洹쇨굅濡??뺤젙?섏? ?딆뒿?덈떎.  
> CAPA / Speakeasy / LLM Analyst Assist? ?④퍡 ?댁꽍?⑸땲??

---

# 9. Speakeasy Worker Interface

## 9.1 Worker Status Flow

```text
QUEUED
   ??
RUNNING
   ??
COMPLETED
```

?ㅻ쪟 諛쒖깮 ??

```text
RUNNING
   ??
FAILED
```

## 9.2 Speakeasy Result

```json
{
  "analysis_id": "a_20260907_000001",
  "tool": "SPEAKEASY",
  "status": "COMPLETED",
  "behavior": {
    "processes": [],
    "api_calls": [],
    "files": [],
    "registry": [],
    "network": []
  },
  "error": null
}
```

?ㅽ뙣 ?덉떆:

```json
{
  "analysis_id": "a_20260907_000001",
  "tool": "SPEAKEASY",
  "status": "FAILED",
  "behavior": null,
  "error": {
    "code": "SPEAKEASY_EXECUTION_FAILED",
    "message": "..."
  }
}
```

---

# 10. Deep Analysis Status Interface

```json
{
  "deep_analysis_status": {
    "capa": "COMPLETED",
    "floss": "COMPLETED",
    "speakeasy": "RUNNING",
    "cape": "NOT_REQUIRED"
  }
}
```

> CAPE???꾩옱 ?먮룞 ?뚯씠?꾨씪???꾩닔 援ы쁽 ??곸씠 ?꾨땲硫? ?몃? Behavioral Report ?쒖슜 ?щ????곕씪 蹂寃쎈맆 ???덉뒿?덈떎.

---

# 11. MITRE ATT&CK Evidence Interface

```json
{
  "evidence": [
    {
      "technique_id": "T1059",
      "technique_name": "Command and Scripting Interpreter",
      "sources": ["CAPA", "SPEAKEASY"],
      "summary": "Command execution related behavior detected."
    },
    {
      "technique_id": "T1055",
      "technique_name": "Process Injection",
      "sources": ["SPEAKEASY"],
      "summary": "Process injection related behavior observed."
    }
  ]
}
```

---

# 12. LLM Analyst Assist Interface

## 12.1 LLM ?낅젰

```json
{
  "sample_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
  "initial_verdict": "HIGH_RISK_UNCERTAIN",
  "evidence": [
    {
      "technique_id": "T1059",
      "technique_name": "Command and Scripting Interpreter",
      "sources": ["CAPA"],
      "summary": "Command execution related behavior detected."
    }
  ]
}
```

## 12.2 LLM 異쒕젰

```json
{
  "analysis_id": "a_20260907_000001",
  "llm_summary": {
    "summary": "遺꾩꽍 寃곌낵 ?붿빟",
    "suspicious_behaviors": [
      "?섏떖 ?됱쐞 1",
      "?섏떖 ?됱쐞 2"
    ],
    "analyst_notes": "異붽? ?뺤씤???꾩슂???ы빆"
  }
}
```

> **Critical**  
> LLM Summary??**遺꾩꽍媛 蹂댁“ ?뺣낫**?낅땲??  
> CAPA/Speakeasy ???먮낯 Evidence瑜??泥댄븯吏 ?딆뒿?덈떎.

---

# 13. Final Assessment Interface

```json
{
  "analysis_id": "a_20260907_000001",
  "initial_verdict": "HIGH_RISK_UNCERTAIN",
  "final_verdict": "MALICIOUS",
  "analyst_final_verdict": null,
  "evidence": [],
  "llm_summary": {},
  "completed_at": "2026-09-07T14:35:00+09:00"
}
```

## `initial_verdict`

```text
AUTO_BENIGN
AUTO_MALICIOUS
HIGH_RISK_UNCERTAIN
```

## `final_verdict`

```text
BENIGN
MALICIOUS
UNCERTAIN
```

> **Review-first Policy**  
> ?쒖뒪?쒖? ?ㅽ깘/誘명깘??理쒖냼?뷀븯湲??꾪빐 湲곕낯?곸쑝濡??먮룞 ?먯젙??蹂댁닔?곸쑝濡?吏꾪뻾?섎ŉ, 遺덊솗?ㅽ븳 寃쎌슦 `UNCERTAIN`?쇰줈 遺꾨쪟?섏뿬 ?꾨Ц媛??寃??MANUAL_REVIEW)瑜??쒖븞?⑸땲??

## `analyst_final_verdict`

```text
BENIGN
MALICIOUS
```

?꾩슂??寃쎌슦 `UNRESOLVED` 異붽? ?щ?瑜?蹂꾨룄濡?寃곗젙?⑸땲??

---

# 14. Analyst Feedback Interface

PATCH /analyses/{analysis_id}/verdict

**Request**
`json
{
  "analyst_final_verdict": "MALICIOUS",
  "analyst_notes": "Suspicious process injection behavior confirmed.",
  "reviewer_id": "analyst_1",
  "expected_revision": 0
}
`

**Response**
`json
{
  "analysis_id": "a_20260915_000001",
  "revision": 1,
  "analyst_final_verdict": "MALICIOUS",
  "analyst_notes": "Suspicious process injection behavior confirmed.",
  "reviewer_id": "analyst_1",
  "reviewed_at": "2026-09-15T15:00:00Z"
}
`

> 현재 모델 재학습 자동화 방식은 M4 이후 별도 결정합니다.

---

# 15. REST API Interface

?꾨옒 Endpoint??沅뚯옣 珥덉븞?대ŉ Backend 援ы쁽 ??理쒖쥌 ?뺤젙?⑸땲??

遺꾩꽍 ?붿껌? ?ъ링遺꾩꽍??鍮꾨룞湲곕줈 ?댁뼱吏????덉쑝誘濡?`POST /analyses`, `POST /batches`???묒뾽 ?묒닔 ??`analysis_id` ?먮뒗 `batch_id`瑜?諛섑솚?섎뒗 援ъ“瑜?沅뚯옣?⑸땲??

```text
HTTP 202 Accepted
```

瑜?湲곕낯 ?묐떟 ?꾨낫濡??ъ슜?⑸땲??

| Method | Endpoint | ?ㅻ챸 |
|---|---|---|
| `POST` | `/analyses` | ?⑥씪 PE 遺꾩꽍 ?붿껌 |
| `GET` | `/analyses/{analysis_id}` | ?꾩껜 遺꾩꽍 寃곌낵 議고쉶 |
| `GET` | `/analyses/{analysis_id}/status` | 遺꾩꽍 ?곹깭 議고쉶 |
| `GET` | `/analyses/{analysis_id}/triage` | Initial Triage 寃곌낵 議고쉶 |
| `GET` | `/analyses/{analysis_id}/deep-analysis` | ?ъ링遺꾩꽍 寃곌낵 議고쉶 |
| `GET` | `/analyses/{analysis_id}/xai` | SHAP 寃곌낵 議고쉶 |
| `POST` | `/batches` | ?ㅼ쨷 ?뚯씪 遺꾩꽍 ?붿껌 |
| `GET` | `/batches/{batch_id}` | Batch 吏꾪뻾 ?곹깭 諛?寃곌낵 議고쉶 |
| `PATCH` | `/analyses/{analysis_id}/verdict` | Analyst Verdict ???|

> ?ㅼ젣 URI 援ъ“??Backend ?대떦 援ы쁽 ?꾩뿉 ? 寃?????뺤젙?⑸땲??

---

# 16. Frontend ??Backend Polling Interface

??

```text
GET /analyses/{analysis_id}/status
```

?묐떟:

```json
{
  "analysis_id": "a_20260907_000001",
  "status": "RUNNING",
  "current_stage": "SPEAKEASY"
}
```

?꾨즺 ??

```json
{
  "analysis_id": "a_20260907_000001",
  "status": "COMPLETED",
  "current_stage": "FINAL_ASSESSMENT"
}
```

---

## 16.1 沅뚯옣 `current_stage`

```text
UPLOAD
INITIAL_ANALYSIS
JRR
CAPA_FLOSS
SPEAKEASY
LLM
FINAL_ASSESSMENT
```

---

# 17. MCP Interface

MCP??湲곗〈 TRUST-Triage 遺꾩꽍 湲곕뒫??AI Agent媛 Tool ?뺥깭濡??ъ슜?????덈룄濡??섎뒗 ?뺤옣 ?명꽣?섏씠?ㅼ엯?덈떎.

## 沅뚯옣 MCP Tools

```text
analyze_sample
get_analysis_status
get_analysis_result
get_deep_analysis_result
get_final_assessment
```

### ?ㅺ퀎 ?먯튃

```text
AI Agent
   ??
MCP Server
   ??
湲곗〈 FastAPI / Service Layer
   ??
TRUST-Triage Pipeline
```

> **Critical**  
> MCP??蹂꾨룄 遺꾩꽍 ?뚯씠?꾨씪?몄쓣 留뚮뱾吏 ?딆뒿?덈떎.  
> Web, REST API, MCP??**?숈씪??Backend 諛?遺꾩꽍 ?붿쭊???ъ궗??*?댁빞 ?⑸땲??

---

# 18. File Storage Interface

```json
{
  "analysis_id": "a_20260907_000001",
  "sha256": "...",
  "file_location": "s3://bucket/object-key"
}
```

## ????먯튃

1. Raw PE ?낅줈??
2. SHA-256 怨꾩궛
3. ?꾩떆 ???
4. 遺꾩꽍 ?섑뻾
5. ?꾩슂??遺꾩꽍 寃곌낵 諛?Feature ???
6. Raw PE ??젣 ?먮뒗 Lifecycle ?뺤콉 ?곸슜

> **TBD**  
> Raw PE 蹂댁〈 湲곌컙 諛?S3 Lifecycle ?몃? ?뺤콉? AWS/蹂댁븞 ?뺤콉 ?뺤젙 ??諛섏쁺?⑸땲??

---

# 19. Database ???理쒖냼 ??ぉ

## Analysis Metadata

- `analysis_id`
- `batch_id`
- `sha256`
- filename
- created_at
- completed_at
- status

## Initial Analysis

- LightGBM probability
- XGBoost probability
- calibrated probability
- disagreement
- OOD score
- difficulty score
- initial verdict
- route

## XAI

- SHAP `top_features`

## Deep Analysis

- CAPA result
- FLOSS result
- Speakeasy result
- Deep Analysis status

## Evidence

- MITRE ATT&CK normalized evidence

## Final

- LLM summary
- final verdict
- analyst final verdict
- analyst comment

---

# 20. Error Interface

```json
{
  "analysis_id": "a_20260907_000001",
  "status": "FAILED",
  "error": {
    "stage": "SPEAKEASY",
    "code": "SPEAKEASY_EXECUTION_FAILED",
    "message": "Analysis failed."
  }
}
```

### 沅뚯옣 Error Stage

```text
UPLOAD
FEATURE_EXTRACTION
MODEL_INFERENCE
CALIBRATION
JRR
SHAP
CAPA
FLOSS
QUEUE
SPEAKEASY
LLM
DATABASE
FINAL_ASSESSMENT
```

> **Critical**  
> ??紐⑤뱢???ㅽ뙣媛 ?꾩껜 遺꾩꽍???먯씤???????녿뒗 `500 error` ?섎굹濡쒕쭔 ?⑥? ?딅룄濡??ㅽ뙣 Stage瑜?湲곕줉?⑸땲??

---

# 21. ?대떦 ?곸뿭蹂??뺤씤 ??ぉ

## Frontend

- API ?꾨뱶紐낆쓣 ?꾩쓽濡?蹂寃쏀븯吏 ?딆쓬
- Polling ?곹깭 Enum 以??
- Batch 寃곌낵瑜?`batch_id` + 媛쒕퀎 `analysis_id` 湲곗??쇰줈 ?쒖떆
- SHAP怨?Behavioral Evidence瑜??붾㈃?먯꽌 遺꾨━

## Backend / DB

- 怨듯넻 ID ?앹꽦 諛?愿由?
- REST API 怨꾩빟 ?좎?
- JRR / Deep Analysis / Final Verdict瑜?遺꾨━ ???
- Worker媛 議고쉶 媛?ν븳 ?뚯씪 ?꾩튂 諛?Job ?뺣낫 ?쒓났

## Deep Analysis / Task Queue

- SQS Message Body 援ъ“ 以??
- `analysis_id` 湲곗? Idempotency 泥섎━
- ?곹깭媛??낅뜲?댄듃
- CAPA / FLOSS / Speakeasy 寃곌낵 ?쒖? 援ъ“ 諛섑솚
- Worker ?ㅽ뙣 ??Error Interface 以??
- SQS ?뺤젙 ??Visibility Timeout / Retry / DLQ ?뺤콉??Service Architecture? ?④퍡 諛섏쁺

## AWS / Infrastructure

- Raw PE ?꾩떆 ??μ냼 援ъ꽦
- Main Server ??Worker ??DB 媛??묎렐 沅뚰븳 愿由?
- Queue 諛?Storage 沅뚰븳 理쒖냼??
- Secret / API Key瑜?肄붾뱶??吏곸젒 ??ν븯吏 ?딆쓬

## System Integration

- 紐⑤뱢 媛??꾨뱶紐?諛??곹깭 Enum 寃利?
- End-to-End ?곗씠???먮쫫 ?뺤씤
- Web / REST API / MCP媛 ?숈씪 遺꾩꽍 寃곌낵瑜??ъ슜?섎뒗吏 寃利?

---

# 22. ?꾩옱 TBD ??ぉ

- [ ] Task Queue 理쒖쥌 ?뺤젙: **AWS SQS ?곗꽑??* (? ?뺤젙 ??TBD ?쒓굅)
- [ ] Main Server / Worker ?⑥씪쨌遺꾩궛 諛곗튂 理쒖쥌 援ъ“
- [ ] PostgreSQL 諛고룷 諛⑹떇: EC2 / RDS ??
- [ ] Raw PE ???諛⑹떇 諛?蹂댁〈 湲곌컙
- [ ] Batch 理쒕? ?뚯씪 ??/ ?뚯씪 ?ш린 ?쒗븳
- [ ] ZIP ?낅젰 吏???щ?
- [ ] CAPA + FLOSS ??Speakeasy Tier 吏꾩엯 議곌굔
- [ ] `final_verdict` 理쒖쥌 Enum
- [ ] MCP 援ы쁽 踰붿쐞 諛?Tool 紐⑸줉
- [ ] LLM API 諛?Prompt/Output Schema ?뺤젙
- [ ] Final Assessment ?먮룞 ?먯젙 濡쒖쭅

---

# 23. 蹂寃?愿由?洹쒖튃

```text
1. interface_spec.md ?섏젙
        ??
2. 愿???대떦??寃??
        ??
3. Backend / Worker / Frontend 肄붾뱶 諛섏쁺
        ??
4. Integration Test
```

> **Critical**  
> ?듯빀 ?④퀎?먯꽌??**肄붾뱶瑜?癒쇱? 蹂寃쏀븯怨?臾몄꽌瑜??섏쨷??留욎텛??諛⑹떇蹂대떎, ?명꽣?섏씠??紐낆꽭瑜?癒쇱? ?⑹쓽????援ы쁽?섎뒗 諛⑹떇**??湲곕낯 ?먯튃?쇰줈 ?⑸땲??

---

# 24. ?듭떖 怨꾩빟 ?붿빟

```text
媛쒕퀎 遺꾩꽍 ID       ??analysis_id
Batch ID           ??batch_id
?뚯씪 ?앸퀎           ??sha256

遺꾩꽍 ?곹깭           ??QUEUED / RUNNING / COMPLETED / FAILED / NOT_REQUIRED

JRR ?먯젙            ??AUTO_BENIGN / AUTO_MALICIOUS / HIGH_RISK_UNCERTAIN
JRR ????ъ쑀         ??reason
JRR 諛쒗쁽 ?좏샇 ?꾩껜     ??triggered_signals
Uncertain Probability ??Gray Zone ?ㅻ챸??Label (蹂꾨룄 ?뺣쪧 ?꾨뱶 ?꾨떂)

紐⑤뜽 洹쇨굅           ??top_features (SHAP)
?됱쐞 洹쇨굅           ??evidence (CAPA/FLOSS/Speakeasy/MITRE)

鍮꾨룞湲??묒뾽         ??CAPA/FLOSS ???꾩슂 ??SQS ??Speakeasy Worker
SQS 硫붿떆吏           ??analysis_id + sha256 + file_location + requested_stage
Raw PE              ??硫붿떆吏/DB??吏곸젒 ?쎌엯 湲덉?

?먯젙 ?대젰           ??initial_verdict
                      final_verdict
                      analyst_final_verdict

Web / REST / MCP    ???숈씪 Backend 諛?遺꾩꽍 ?뚯씠?꾨씪???ъ슜
```

