import re

with open("app.py", "r", encoding="utf-8") as f:
    content = f.read()

original_len = len(content)

# --- 1. Add imports ---
OLD_IMPORTS = """from werkzeug.security import generate_password_hash, check_password_hash

from config import Config"""

NEW_IMPORTS = """from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import base64

from config import Config"""

assert OLD_IMPORTS in content, "Import anchor not found - aborting, no changes made."
content = content.replace(OLD_IMPORTS, NEW_IMPORTS, 1)

# --- 2. Replace login route with 2FA-aware version + add verify-2fa route ---
OLD_LOGIN = """@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session.permanent = True
            session["user_id"] = user.id
            session["username"] = user.username
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
        return redirect(url_for("login"))

    return render_template("login.html")"""

NEW_LOGIN = """@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            if user.totp_enabled:
                session["pending_2fa_user_id"] = user.id
                return redirect(url_for("login_verify_2fa"))
            session.permanent = True
            session["user_id"] = user.id
            session["username"] = user.username
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/login/verify-2fa", methods=["GET", "POST"])
def login_verify_2fa():
    pending_id = session.get("pending_2fa_user_id")
    if not pending_id:
        return redirect(url_for("login"))
    user = User.query.get(pending_id)
    if not user:
        session.pop("pending_2fa_user_id", None)
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip().replace(" ", "")
        totp = pyotp.TOTP(user.totp_secret)

        if totp.verify(code, valid_window=1):
            session.pop("pending_2fa_user_id", None)
            session.permanent = True
            session["user_id"] = user.id
            session["username"] = user.username
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("dashboard"))

        backup_codes = json.loads(user.backup_codes) if user.backup_codes else []
        matched_index = None
        for i, bc_hash in enumerate(backup_codes):
            if check_password_hash(bc_hash, code):
                matched_index = i
                break

        if matched_index is not None:
            backup_codes.pop(matched_index)
            user.backup_codes = json.dumps(backup_codes)
            db.session.commit()
            session.pop("pending_2fa_user_id", None)
            session.permanent = True
            session["user_id"] = user.id
            session["username"] = user.username
            flash("Logged in with a backup code. Consider regenerating your codes in settings.", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid authentication code.", "error")
        return redirect(url_for("login_verify_2fa"))

    return render_template("login_verify_2fa.html")"""

assert OLD_LOGIN in content, "Login route anchor not found - aborting, no changes made."
content = content.replace(OLD_LOGIN, NEW_LOGIN, 1)

# --- 3. Insert 2FA settings routes before admin_required ---
OLD_ANCHOR = """    return redirect(url_for("dashboard"))


def admin_required(f):"""

NEW_ANCHOR = '''    return redirect(url_for("dashboard"))


@app.route("/settings/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    user = User.query.get(session["user_id"])

    if user.totp_enabled:
        flash("Two-factor authentication is already enabled.", "success")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        code = request.form.get("code", "").strip().replace(" ", "")
        if not user.totp_secret:
            flash("2FA setup session expired. Start again.", "error")
            return redirect(url_for("setup_2fa"))

        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(code, valid_window=1):
            raw_backup_codes = [secrets.token_hex(4) for _ in range(8)]
            hashed_backup_codes = [generate_password_hash(c) for c in raw_backup_codes]
            user.totp_enabled = True
            user.backup_codes = json.dumps(hashed_backup_codes)
            db.session.commit()

            try:
                from detectors.email_utils import send_email
                html_body = (
                    "<div style=\\"font-family: Arial, sans-serif;\\">"
                    "<h2>Two-Factor Authentication Enabled</h2>"
                    "<p>Hi " + user.username + ", 2FA has just been enabled on your PhishIQ account.</p>"
                    "<p>If this was not you, change your password immediately.</p>"
                    "</div>"
                )
                send_email(user.email, "PhishIQ: 2FA Enabled", html_body)
            except Exception:
                pass

            flash("Two-factor authentication enabled. Save your backup codes now.", "success")
            return render_template("backup_codes.html", codes=raw_backup_codes)

        flash("Invalid code. Try again.", "error")
        return redirect(url_for("setup_2fa"))

    secret = pyotp.random_base32()
    user.totp_secret = secret
    db.session.commit()

    provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user.email, issuer_name="PhishIQ"
    )

    qr_img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return render_template("setup_2fa.html", qr_b64=qr_b64, secret=secret)


@app.route("/settings/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    user = User.query.get(session["user_id"])
    password = request.form.get("password", "")
    if not check_password_hash(user.password_hash, password):
        flash("Incorrect password.", "error")
        return redirect(url_for("dashboard"))
    user.totp_enabled = False
    user.totp_secret = None
    user.backup_codes = None
    db.session.commit()
    flash("Two-factor authentication disabled.", "success")
    return redirect(url_for("dashboard"))


def admin_required(f):'''

count = content.count(OLD_ANCHOR)
assert count == 1, f"Expected 1 match for admin_required anchor, found {count} - aborting."
content = content.replace(OLD_ANCHOR, NEW_ANCHOR, 1)

with open("app.py", "w", encoding="utf-8") as f:
    f.write(content)

print(f"app.py patched successfully. {original_len} -> {len(content)} chars.")
