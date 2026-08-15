path = "detectors/url_analyzer.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

new_ml_call = """    decoded_domain = decode_domain_for_ml(domain)
    if decoded_domain != domain:
        ml_input_url = url_original.replace(domain, decoded_domain, 1)
    else:
        ml_input_url = url_original

    ml_prob = ml_url_probability(ml_input_url)
    ngram_prob = ml_url_ngram_probability(ml_input_url)"""

old_ml_call = """    ml_prob = ml_url_probability(url_original)
    ngram_prob = ml_url_ngram_probability(url_original)"""

if new_ml_call not in content:
    raise SystemExit("Could not find ML block to revert - aborting.")
content = content.replace(new_ml_call, old_ml_call, 1)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("Reverted ML input back to url_original.")
