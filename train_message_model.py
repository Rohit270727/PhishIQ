import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

df = pd.read_csv("data/messages.csv")
df = df.dropna(subset=["text", "label"])
df["text"] = df["text"].astype(str)
df = df[df["text"].str.strip() != ""]

def to_binary(v):
    if isinstance(v, str):
        return 1 if v.strip().lower() in ("spam", "1", "scam", "phishing") else 0
    return int(v)

df["label"] = df["label"].apply(to_binary)

X_train, X_test, y_train, y_test = train_test_split(
    df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
)

vectorizer = TfidfVectorizer(max_features=3000, ngram_range=(1, 2), stop_words="english")
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

model = LogisticRegression(max_iter=1000, class_weight="balanced")
model.fit(X_train_vec, y_train)

preds = model.predict(X_test_vec)
print(classification_report(y_test, preds, target_names=["ham", "spam/scam"]))

joblib.dump(model, "ml_models/message_model.pkl")
joblib.dump(vectorizer, "ml_models/message_vectorizer.pkl")
print("Saved ml_models/message_model.pkl and ml_models/message_vectorizer.pkl")
