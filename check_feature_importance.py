import joblib
from detectors.feature_extractor import FEATURE_ORDER

model = joblib.load("ml_models/url_model.pkl")
importances = model.feature_importances_

ranked = sorted(zip(FEATURE_ORDER, importances), key=lambda x: x[1], reverse=True)
for name, score in ranked:
    print(f"{name:<25} {score:.4f}")
