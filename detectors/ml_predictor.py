import os
import joblib
from detectors.feature_extractor import extract_url_features, features_to_vector

URL_MODEL_PATH = "ml_models/url_model.pkl"
URL_NGRAM_MODEL_PATH = "ml_models/url_ngram_model.pkl"
URL_NGRAM_VEC_PATH = "ml_models/url_ngram_vectorizer.pkl"
MSG_MODEL_PATH = "ml_models/message_model.pkl"
MSG_VEC_PATH = "ml_models/message_vectorizer.pkl"

_url_model = None
_url_ngram_model = None
_url_ngram_vectorizer = None
_msg_model = None
_msg_vectorizer = None

def _load_url_model():
    global _url_model
    if _url_model is None and os.path.exists(URL_MODEL_PATH):
        _url_model = joblib.load(URL_MODEL_PATH)
    return _url_model

def _load_url_ngram_model():
    global _url_ngram_model, _url_ngram_vectorizer
    if _url_ngram_model is None and os.path.exists(URL_NGRAM_MODEL_PATH) and os.path.exists(URL_NGRAM_VEC_PATH):
        _url_ngram_model = joblib.load(URL_NGRAM_MODEL_PATH)
        _url_ngram_vectorizer = joblib.load(URL_NGRAM_VEC_PATH)
    return _url_ngram_model, _url_ngram_vectorizer

def _load_msg_model():
    global _msg_model, _msg_vectorizer
    if _msg_model is None and os.path.exists(MSG_MODEL_PATH) and os.path.exists(MSG_VEC_PATH):
        _msg_model = joblib.load(MSG_MODEL_PATH)
        _msg_vectorizer = joblib.load(MSG_VEC_PATH)
    return _msg_model, _msg_vectorizer

def ml_url_probability(url):
    model = _load_url_model()
    if model is None:
        return None
    vec = [features_to_vector(extract_url_features(url))]
    proba = model.predict_proba(vec)[0]
    classes = list(model.classes_)
    phishing_idx = classes.index(1) if 1 in classes else -1
    return float(proba[phishing_idx]) if phishing_idx >= 0 else None

def ml_url_ngram_probability(url):
    model, vectorizer = _load_url_ngram_model()
    if model is None or vectorizer is None:
        return None
    vec = vectorizer.transform([str(url)])
    proba = model.predict_proba(vec)[0]
    classes = list(model.classes_)
    phishing_idx = classes.index(1) if 1 in classes else -1
    return float(proba[phishing_idx]) if phishing_idx >= 0 else None

def ml_message_probability(text):
    model, vectorizer = _load_msg_model()
    if model is None or vectorizer is None:
        return None
    vec = vectorizer.transform([text])
    proba = model.predict_proba(vec)[0]
    classes = list(model.classes_)
    scam_idx = classes.index(1) if 1 in classes else -1
    return float(proba[scam_idx]) if scam_idx >= 0 else None
