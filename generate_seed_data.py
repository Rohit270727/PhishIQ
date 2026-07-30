import csv
import random

random.seed(42)

legit_domains = ["google.com", "amazon.com", "github.com", "wikipedia.org", "microsoft.com",
                  "flipkart.com", "sbi.co.in", "icicibank.com", "linkedin.com", "netflix.com"]
phish_patterns = [
    "http://{brand}-secure-login.tk/verify",
    "http://{brand}.account-update.xyz/confirm",
    "http://192.168.{a}.{b}/{brand}/login",
    "http://secure-{brand}-billing.club/signin",
    "http://{brand}verify.win/update-account",
    "http://{brand}-support.top/reset-password",
]
brands = ["paypal", "amazon", "google", "netflix", "hdfc", "sbi", "microsoft", "apple", "instagram", "flipkart"]

rows = []
for d in legit_domains:
    for path in ["/", "/home", "/products", "/about", "/contact", "/blog", "/help", "/login"]:
        rows.append((f"https://{d}{path}", 0))
    for _ in range(15):
        sub = random.choice(["www", "shop", "mail", "support", "app"])
        rows.append((f"https://{sub}.{d}/page{random.randint(1,999)}", 0))

for _ in range(300):
    pattern = random.choice(phish_patterns)
    url = pattern.format(brand=random.choice(brands), a=random.randint(1,255), b=random.randint(1,255))
    rows.append((url, 1))

random.shuffle(rows)
with open("data/urls.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["url", "label"])
    w.writerows(rows)

legit_msgs = [
    "Hey, are we still on for lunch tomorrow?",
    "Your order has been shipped and will arrive in 3-5 days.",
    "Meeting rescheduled to 3 PM, see you then.",
    "Thanks for the update, I will review it tonight.",
    "Reminder: your appointment is confirmed for Monday.",
    "Can you send me the report when you get a chance?",
    "Happy birthday! Hope you have a great day.",
    "The package was delivered to your address today.",
    "Let's catch up this weekend if you're free.",
    "Your monthly statement is now available in the app.",
]
scam_msgs = [
    "URGENT! Your account has been suspended, verify now: bit.ly/{c}",
    "Congratulations! You have WON a FREE prize, claim your CASH now: bit.ly/{c}",
    "Dear customer, your bank account will be blocked. Verify your PIN immediately: bit.ly/{c}",
    "Final notice: your package is held. Pay a small fee to release: bit.ly/{c}",
    "You have been selected for a lottery jackpot! Claim your reward now: bit.ly/{c}",
    "Security alert: unusual login detected. Confirm your password here: bit.ly/{c}",
    "Your card has been charged. If this wasn't you, verify OTP now: bit.ly/{c}",
    "ACT NOW! Limited time offer, free gift card, click immediately: bit.ly/{c}",
]

rows2 = [(m, 0) for m in legit_msgs for _ in range(20)]
rows2 += [(m.format(c=random.randint(1000,9999)), 1) for m in scam_msgs for _ in range(20)]
random.shuffle(rows2)
with open("data/messages.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["text", "label"])
    w.writerows(rows2)

print(f"Generated {len(rows)} URL rows and {len(rows2)} message rows.")
