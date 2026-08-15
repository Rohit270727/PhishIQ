content = open("app.py", encoding="utf-8").read()

old = """            sender_domain = None
            if ext == "eml":
                from detectors.file_extractor import extract_sender_domain
                sender_domain = extract_sender_domain(filepath, ext)

        if not text:
            flash("Please enter a message or upload a file.", "error")
            return redirect(url_for("scan_message"))

        result = analyze_message(text, sender_domain=locals().get("sender_domain"))"""

new = """            sender_domain = None
            eml_filepath = None
            if ext == "eml":
                from detectors.file_extractor import extract_sender_domain
                sender_domain = extract_sender_domain(filepath, ext)
                eml_filepath = filepath

        if not text:
            flash("Please enter a message or upload a file.", "error")
            return redirect(url_for("scan_message"))

        result = analyze_message(
            text,
            sender_domain=locals().get("sender_domain"),
            eml_filepath=locals().get("eml_filepath")
        )"""

assert old in content, "target block not found in app.py — aborting, no changes made"
content = content.replace(old, new, 1)
open("app.py", "w", encoding="utf-8").write(content)
print("app.py patched — eml_filepath wired through")
