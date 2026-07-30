import pandas as pd

# Clean URLs
urls_df = pd.read_csv("data/raw_urls.csv")
urls_df = urls_df.dropna(subset=["URL", "Label"])
urls_df["Label"] = urls_df["Label"].str.strip().str.lower().map({"bad": 1, "good": 0})
urls_df = urls_df.dropna(subset=["Label"])
urls_df["Label"] = urls_df["Label"].astype(int)
urls_clean = urls_df.rename(columns={"URL": "url", "Label": "label"})[["url", "label"]]
urls_clean.to_csv("data/urls.csv", index=False)
print(f"Cleaned URLs: {urls_clean.shape[0]} rows")
print(urls_clean["label"].value_counts())

# Clean messages
msg_df = pd.read_csv("data/raw_messages.csv", encoding="latin-1")
msg_df = msg_df[["v1", "v2"]].dropna()
msg_df["v1"] = msg_df["v1"].str.strip().str.lower().map({"spam": 1, "ham": 0})
msg_df = msg_df.dropna(subset=["v1"])
msg_df["v1"] = msg_df["v1"].astype(int)
msg_clean = msg_df.rename(columns={"v2": "text", "v1": "label"})[["text", "label"]]
msg_clean.to_csv("data/messages.csv", index=False)
print(f"Cleaned messages: {msg_clean.shape[0]} rows")
print(msg_clean["label"].value_counts())
