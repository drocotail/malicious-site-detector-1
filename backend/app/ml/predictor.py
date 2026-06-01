"""
ML 모델 예측 모듈

verdict_engine.py에서 호출하여 ML 기반 피싱 점수를 보조 신호로 사용.
모델이 없으면 None 반환 (graceful degradation).
"""

import os
import pickle
import logging

from app.ml.features import extract

logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "saved_model", "phishing_model.pkl")

_model = None
_model_loaded = False


def _load_model():
    global _model, _model_loaded
    if _model_loaded:
        return
    _model_loaded = True
    if not os.path.exists(MODEL_PATH):
        logger.warning("ML 모델 파일 없음: %s — ML 점수 비활성화", MODEL_PATH)
        return
    try:
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
        logger.info("ML 모델 로드 완료: %s", MODEL_PATH)
    except Exception as e:
        logger.error("ML 모델 로드 실패: %s", e)


def predict(url: str) -> dict | None:
    """
    URL → ML 피싱 점수 반환.

    반환값:
        {
            "ml_score": 0~100,       # 피싱 의심도 (높을수록 위험)
            "ml_label": "phishing" | "normal",
            "confidence": 0.0~1.0,  # 모델 확신도
        }
    모델 없으면 None 반환.
    """
    _load_model()
    if _model is None:
        return None

    try:
        features = extract(url)
        prob = _model.predict_proba([features])[0]
        phishing_prob = float(prob[1])  # 클래스 1 = 피싱

        return {
            "ml_score": round(phishing_prob * 100),
            "ml_label": "phishing" if phishing_prob >= 0.5 else "normal",
            "confidence": round(max(phishing_prob, 1 - phishing_prob), 3),
        }
    except Exception as e:
        logger.error("ML 예측 실패 (url=%s): %s", url, e)
        return None
