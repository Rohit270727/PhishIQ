from detectors.link_mismatch_detector import check_link_text_mismatch

html_mismatch = "<p>Click <a href=\"http://evil-phish.tk/x\">www.paypal.com</a> to verify.</p>"
html_honest = "<p>Visit <a href=\"https://paypal.com/help\">paypal.com</a> for support.</p>"

print("Mismatch case:", check_link_text_mismatch(html_mismatch))
print("Honest case:  ", check_link_text_mismatch(html_honest))
