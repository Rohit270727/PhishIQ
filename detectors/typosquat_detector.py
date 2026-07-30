KNOWN_BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "facebook", "instagram",
    "netflix", "bankofamerica", "chase", "wellsfargo", "flipkart", "sbi", "hdfc",
    "icici", "whatsapp", "linkedin", "twitter", "github", "dropbox", "adobe",
    "yahoo", "outlook", "gmail", "ebay", "walmart"
]

def levenshtein(a, b):
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr_row = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr_row.append(min(
                prev_row[j] + 1,
                curr_row[j - 1] + 1,
                prev_row[j - 1] + cost
            ))
        prev_row = curr_row
    return prev_row[-1]


def check_typosquatting(domain):
    core = domain.split(":")[0]
    parts = core.split(".")
    label = parts[-2] if len(parts) >= 2 else parts[0]
    label = label.lower()

    # Check the full label AND each hyphen-separated segment, since brand
    # impersonation is often padded with extra words (e.g. "paypa1-secure").
    candidates = [label] + [seg for seg in label.split("-") if seg]

    for candidate in candidates:
        for brand in KNOWN_BRANDS:
            if candidate == brand:
                continue
            dist = levenshtein(candidate, brand)
            if 0 < dist <= 2 and len(candidate) >= 4:
                return {
                    "brand": brand,
                    "distance": dist,
                    "message": f"Domain '{candidate}' closely resembles brand '{brand}' (edit distance {dist}) - possible typosquatting"
                }
    return None
