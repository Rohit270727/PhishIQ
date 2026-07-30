import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

df = pd.read_csv("data/urls.csv")
df = df.dropna(subset=["url", "label"])
df["url"] = df["url"].astype(str)

X_train, X_test, y_train, y_test = train_test_split(
    df["url"], df["label"].astype(int), test_size=0.2, random_state=42, stratify=df["label"]
)

vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=5000, min_df=3)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

model = LogisticRegression(max_iter=1000, class_weight="balanced")
model.fit(X_train_vec, y_train)

preds = model.predict(X_test_vec)
print(classification_report(y_test, preds, target_names=["legit", "phishing"]))

joblib.dump(model, "ml_models/url_ngram_model.pkl")
joblib.dump(vectorizer, "ml_models/url_ngram_vectorizer.pkl")
print("Saved ml_models/url_ngram_model.pkl and ml_models/url_ngram_vectorizer.pkl")
