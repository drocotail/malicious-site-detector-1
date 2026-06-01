"""
ML 모델 학습 스크립트 - 별도로 실행하세요.

사용법:
    python -m app.ml.train --data dataset.csv

CSV 형식:
    url,label
    http://example.com,0
    http://phishing.xyz/login,1

데이터셋 추천:
    - UCI Phishing Websites Dataset (Kaggle)
    - PhishTank (https://phishtank.org/developer_info.php)
    - ISCX-URL-2016
"""

import argparse
import os
import pickle

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

from app.ml.features import extract, FEATURE_NAMES

MODEL_PATH = os.path.join(os.path.dirname(__file__), "saved_model", "phishing_model.pkl")


def load_dataset(csv_path: str) -> tuple[np.ndarray, np.ndarray]:
    """CSV 로드 → 피처 행렬, 레이블 배열 반환"""
    df = pd.read_csv(csv_path)

    # 컬럼명 자동 감지
    url_col = next((c for c in df.columns if c.lower() in ("url", "urls", "link")), df.columns[0])
    label_col = next((c for c in df.columns if c.lower() in ("label", "type", "class", "phishing", "is_phishing")), df.columns[-1])

    print(f"URL 컬럼: {url_col}, 레이블 컬럼: {label_col}")
    print(f"전체 데이터: {len(df)}행")

    urls = df[url_col].astype(str).tolist()
    labels = df[label_col].astype(int).tolist()

    print("피처 추출 중...")
    X = []
    valid_labels = []
    for i, (url, label) in enumerate(zip(urls, labels)):
        if i % 1000 == 0:
            print(f"  {i}/{len(urls)}", end="\r")
        try:
            X.append(extract(url))
            valid_labels.append(label)
        except Exception:
            pass

    print(f"\n유효 데이터: {len(X)}행")
    print(f"피싱: {sum(valid_labels)}개 ({sum(valid_labels)/len(valid_labels)*100:.1f}%)")
    print(f"정상: {len(valid_labels)-sum(valid_labels)}개")

    return np.array(X, dtype=float), np.array(valid_labels, dtype=int)


def train(csv_path: str) -> None:
    X, y = load_dataset(csv_path)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Random Forest (속도·성능 균형)
    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_leaf=2,
            class_weight="balanced",  # 피싱 데이터 불균형 보정
            random_state=42,
            n_jobs=-1,
        )),
    ])

    print("\n모델 학습 중...")
    model.fit(X_train, y_train)

    # 평가
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print("\n=== 평가 결과 ===")
    print(classification_report(y_test, y_pred, target_names=["정상", "피싱"]))
    print(f"AUC-ROC: {roc_auc_score(y_test, y_prob):.4f}")

    # 피처 중요도 (상위 10개)
    clf = model.named_steps["clf"]
    importances = sorted(zip(FEATURE_NAMES, clf.feature_importances_), key=lambda x: -x[1])
    print("\n=== 피처 중요도 (상위 10개) ===")
    for name, imp in importances[:10]:
        print(f"  {name}: {imp:.4f}")

    # 교차 검증
    cv_scores = cross_val_score(model, X, y, cv=5, scoring="f1", n_jobs=-1)
    print(f"\n5-Fold CV F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # 모델 저장
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    print(f"\n모델 저장 완료: {MODEL_PATH}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, help="학습 CSV 파일 경로")
    args = parser.parse_args()
    train(args.data)
