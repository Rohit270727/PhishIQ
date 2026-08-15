with open("asyncjob_model.py", encoding="utf-8-sig") as f:
    snippet = f.read()

with open("models.py", "a", encoding="utf-8", newline="") as f:
    f.write(snippet)

print("appended AsyncScanJob to models.py")
