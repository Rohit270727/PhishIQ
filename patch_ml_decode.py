import re

path = "detectors/url_analyzer.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

old_import = "from detectors.homograph_detector import check_homograph"
new_import = "from detectors.homograph_detector import check_homograph, decode_domain_for_ml"
if old_import not in content:
    raise SystemExit("Could not find homograph import - aborting, no changes made.")
content = content.replace(old_import, new_import, 1)

old_ml_call = '''    ml_prob = ml_url_probability(url_original)
    ngram_prob = ml_url_ngram_probability(url_original)'''

new_ml_call = '''    decoded_domain = decode_domain_for_ml(domain)
    if decoded_domain != domain:
        ml_input_url = url_original.replace(domain, decoded_domain, 1)
    else:
        ml_input_url = url_original

    ml_prob = ml_url_probability(ml_input_url)
    ngram_prob = ml_url_ngram_probability(ml_input_url)'''

if old_ml_call not in content:
    raise SystemExit("Could not find ML call block - aborting, no changes made.")
content = content.replace(old_ml_call, new_ml_call, 1)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("url_analyzer.py now feeds decoded domains to ML models.")
