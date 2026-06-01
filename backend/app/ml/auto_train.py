"""
공개 데이터셋을 자동 다운로드 후 모델 학습.

사용법:
    docker compose exec backend python -m app.ml.auto_train
"""

import io
import os
import pickle

import numpy as np
import pandas as pd
import urllib.request
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from app.ml.features import extract, FEATURE_NAMES

MODEL_PATH = os.path.join(os.path.dirname(__file__), "saved_model", "phishing_model.pkl")

DATASET_URL = (
    "https://raw.githubusercontent.com/"
    "faizann24/Using-machine-learning-to-detect-malicious-URLs/"
    "master/data/data.csv"
)

# 레이블 정규화 맵
_BENIGN_LABELS  = {"good", "benign", "safe", "legitimate", "0", "0.0", "false"}
_PHISH_LABELS   = {"bad", "phishing", "malicious", "malware", "1", "1.0", "true"}


def _to_int_label(v) -> int | None:
    """레이블 → 0(정상) / 1(피싱) / None(무효)"""
    s = str(v).strip().lower()
    if s in _BENIGN_LABELS:
        return 0
    if s in _PHISH_LABELS:
        return 1
    try:
        f = float(s)
        return 1 if f >= 0.5 else 0
    except ValueError:
        return None


def download_dataset() -> pd.DataFrame:
    print(f"데이터셋 다운로드 중: {DATASET_URL}")
    req = urllib.request.Request(DATASET_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    df = pd.read_csv(io.StringIO(raw))
    print(f"다운로드 완료: {len(df)}행")
    return df


def prepare(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    url_col = next(
        (c for c in df.columns if c.lower() in ("url", "urls", "link")), df.columns[0]
    )
    label_col = next(
        (c for c in df.columns if c.lower() in ("label", "type", "class", "result", "is_phishing")),
        df.columns[-1],
    )
    print(f"URL 컬럼: {url_col}  |  레이블 컬럼: {label_col}")

    urls = df[url_col].astype(str).tolist()
    raw_labels = df[label_col].tolist()

    # 레이블 샘플 확인
    unique_sample = {str(v).strip().lower() for v in raw_labels[:200]}
    print(f"레이블 고유값 (샘플): {unique_sample}")

    # ── 1단계: 레이블 변환 ──────────────────────────────────────────────
    labels_int: list[int] = []
    skip_label = 0
    for v in raw_labels:
        converted = _to_int_label(v)
        if converted is None:
            skip_label += 1
            labels_int.append(-1)   # 무효 표시
        else:
            labels_int.append(converted)

    valid_label_count = sum(1 for l in labels_int if l >= 0)
    print(f"레이블 변환: 유효 {valid_label_count}개, 무효 스킵 {skip_label}개")

    # ── 2단계: 피처 추출 (레이블 변환과 분리) ──────────────────────────
    print("피처 추출 중 (시간이 걸릴 수 있습니다)...")
    X: list[list[float]] = []
    y: list[int] = []
    skip_feat = 0

    for i, (url, lbl) in enumerate(zip(urls, labels_int)):
        if i % 5000 == 0:
            print(f"  {i}/{len(urls)}", end="\r", flush=True)
        if lbl < 0:
            continue
        try:
            X.append(extract(url))
            y.append(lbl)
        except Exception:
            skip_feat += 1

    y_arr = np.array(y, dtype=int)
    print(f"\n유효 데이터: {len(X)}행  (피처 오류 스킵: {skip_feat}개)")
    print(f"피싱: {y_arr.sum()}개 ({y_arr.mean()*100:.1f}%)  |  정상: {(y_arr == 0).sum()}개")
    return np.array(X, dtype=float), y_arr


def train(X: np.ndarray, y: np.ndarray) -> Pipeline:
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )),
    ])

    print("\n모델 학습 중...")
    model.fit(X_tr, y_tr)

    y_pred = model.predict(X_te)
    y_prob = model.predict_proba(X_te)[:, 1]

    print("\n=== 평가 결과 ===")
    print(classification_report(y_te, y_pred, target_names=["정상", "피싱"]))
    print(f"AUC-ROC: {roc_auc_score(y_te, y_prob):.4f}")

    clf = model.named_steps["clf"]
    importances = sorted(zip(FEATURE_NAMES, clf.feature_importances_), key=lambda x: -x[1])
    print("\n=== 피처 중요도 (상위 10개) ===")
    for name, imp in importances[:10]:
        print(f"  {name}: {imp:.4f}")

    return model


def main():
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

    df = download_dataset()
    X, y = prepare(df)

    if len(X) == 0:
        print("ERROR: 유효한 데이터가 없습니다. CSV 형식을 확인하세요.")
        return

    model = train(X, y)

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    print(f"\n모델 저장 완료: {MODEL_PATH}")
    print("백엔드를 재시작하면 모델이 자동으로 로드됩니다.")


if __name__ == "__main__":
    main()
