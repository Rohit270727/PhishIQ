import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
from detectors.feature_extractor import extract_url_features, features_to_vector

df = pd.read_csv("data/urls_clean_augmented.csv")
df = df.dropna(subset=["url", "label"])
df = df.drop_duplicates(subset=["url"])

X = [features_to_vector(extract_url_features(u)) for u in df["url"]]
y = df["label"].astype(int).tolist()

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

model = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, class_weight="balanced")
model.fit(X_train, y_train)

preds = model.predict(X_test)
print(classification_report(y_test, preds, target_names=["legit", "phishing"]))

joblib.dump(model, "ml_models/url_model.pkl")
print("Saved ml_models/url_model.pkl")
