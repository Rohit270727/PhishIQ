from detectors.url_analyzer import analyze_url

# label: "legit" or "phishing" — expected ground truth
test_cases = [
    ("https://github.com", "legit"),
    ("https://www.google.com", "legit"),
    ("https://accounts.google.com", "legit"),
    ("https://www.microsoft.com", "legit"),
    ("https://login.microsoftonline.com", "legit"),
    ("https://www.amazon.com", "legit"),
    ("https://smile.amazon.com", "legit"),
    ("https://www.paypal.com", "legit"),
    ("https://mail.yahoo.com", "legit"),
    ("https://outlook.office.com", "legit"),
    ("https://www.linkedin.com/in/someone", "legit"),
    ("https://docs.google.com/document/d/abc123", "legit"),
    ("https://en.wikipedia.org/wiki/Phishing", "legit"),
    ("https://www.dropbox.com/s/abc123/file.pdf", "legit"),
    ("https://www.chase.com/personal/login", "legit"),

    ("http://google.com.fake-login.tk/verify", "phishing"),
    ("http://evil-google.com/", "phishing"),
    ("http://paypal-secure-verify.com/login", "phishing"),
    ("http://185.129.148.19/php/upload.php", "phishing"),
    ("http://appleid-verify-account.com/signin", "phishing"),
    ("http://micros0ft-login.com/account", "phishing"),
    ("http://bit.ly/3xK9zLq", "phishing"),
    ("http://amaz0n-billing-update.top/", "phishing"),
    ("http://secure-chase-banking.xyz/verify-account", "phishing"),
    ("http://facebook.com.confirm-identity.club/", "phishing"),
    ("http://192.168.55.21/wp-login/verify.php", "phishing"),
    ("http://netfl1x-account-suspended.win/login", "phishing"),
    ("http://hsbc-secure-login.loan/banking", "phishing"),
    ("http://wellsfargo.com-alert.ga/verify", "phishing"),
    ("http://update-your-icloud-account.click/", "phishing"),
]

correct = 0
mismatches = []

for url, expected in test_cases:
    result = analyze_url(url)
    verdict = result["verdict"]
    predicted = "legit" if verdict == "Safe" else "phishing"
    ok = predicted == expected
    correct += ok
    marker = "OK " if ok else "XX "
    print(f"{marker} {url}  ->  score={result['score']} verdict={verdict}  (expected {expected})")
    if not ok:
        mismatches.append((url, expected, verdict, result["score"], result["flags"]))

total = len(test_cases)
print()
print(f"Accuracy: {correct}/{total} = {round(100*correct/total, 1)}%")

if mismatches:
    print()
    print("=== MISMATCHES DETAIL ===")
    for url, expected, verdict, score, flags in mismatches:
        print(f"\n{url}")
        print(f"  expected={expected} got={verdict} score={score}")
        for flag, pts in flags:
            print("   -", flag, f"({pts})" if pts else "")
