"""
patch_webhooks.py
Adds webhook subscriptions (register/list/delete) + dispatch on job.complete
and batch.complete to PhishIQ.

Run from D:\PhishIQ with venv active:
    python patch_webhooks.py

Backs up app.py -> app.py.bak_webhooks before writing anything.
"""

import shutil
from pathlib import Path

APP_PY = Path("app.py")

if not APP_PY.exists():
    raise SystemExit("app.py not found in current directory. Run this from D:\\PhishIQ")

src = APP_PY.read_text(encoding="utf-8")


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"ABORTED: expected exactly 1 match for anchor '{label}', found {count}. "
            f"No changes written."
        )
    return text.replace(old, new, 1)


# ---------------------------------------------------------------
# 1. Imports (only added if missing)
# ---------------------------------------------------------------
if "import hmac" not in src:
    src = replace_once(src, "import json", "import json\nimport hmac\nimport hashlib", "imports")
if "import requests" not in src:
    src = src.replace("import hashlib", "import hashlib\nimport requests", 1)
if "import secrets" not in src:
    src = src.replace("import requests", "import requests\nimport secrets", 1)

# ---------------------------------------------------------------
# 2. Hook: success path of _run_async_scan
# ---------------------------------------------------------------
old_success = '''                "flags": [{"reason": r, "points": p} for r, p in result["flags"]]
            })
            job.completed_at = datetime.utcnow()
            db.session.commit()
        except Exception as e:'''

new_success = '''                "flags": [{"reason": r, "points": p} for r, p in result["flags"]]
            })
            job.completed_at = datetime.utcnow()
            db.session.commit()

            _dispatch_webhook(user_id, "job.complete", {
                "job_id": job_id,
                "status": "complete",
                "url": url,
                "score": result["score"],
                "verdict": result["verdict"],
            })
            if job.batch_id:
                _check_batch_complete(job.batch_id)
        except Exception as e:'''

src = replace_once(src, old_success, new_success, "success hook")

# ---------------------------------------------------------------
# 3. Hook: failure path of _run_async_scan
# ---------------------------------------------------------------
old_failure = '''            job.status = "failed"
            job.error = str(e)
            job.completed_at = datetime.utcnow()
            db.session.commit()'''

new_failure = '''            job.status = "failed"
            job.error = str(e)
            job.completed_at = datetime.utcnow()
            db.session.commit()

            _dispatch_webhook(user_id, "job.complete", {
                "job_id": job_id,
                "status": "failed",
                "url": url,
                "error": str(e),
            })
            if job.batch_id:
                _check_batch_complete(job.batch_id)'''

src = replace_once(src, old_failure, new_failure, "failure hook")

# ---------------------------------------------------------------
# 4. Helpers: inserted right before _batch_executor definition
# ---------------------------------------------------------------
old_batch_executor = "_batch_executor = ThreadPoolExecutor(max_workers=5)"

helpers = '''def _dispatch_webhook(user_id, event_type, payload):
    """Signs and POSTs payload to all active webhook subscriptions for
    user_id that are listening for event_type (or "all"). Failures are
    logged but never raised - a broken webhook must never break a scan."""
    subs = WebhookSubscription.query.filter_by(user_id=user_id, is_active=True).all()
    body = json.dumps(payload, default=str).encode("utf-8")

    for sub in subs:
        if sub.event_type not in (event_type, "all"):
            continue
        signature = hmac.new(sub.secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        try:
            resp = requests.post(
                sub.url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-PhishIQ-Event": event_type,
                    "X-PhishIQ-Signature": f"sha256={signature}",
                },
                timeout=5,
            )
            sub.last_status_code = resp.status_code
        except requests.RequestException as exc:
            app.logger.warning(f"Webhook dispatch failed for subscription {sub.id}: {exc}")
            sub.last_status_code = None
        finally:
            sub.last_triggered_at = datetime.utcnow()
            db.session.commit()


def _check_batch_complete(batch_id):
    """After a job finishes, checks whether every job in its batch has
    reached a terminal state. If so, fires a batch.complete webhook.
    Note: with concurrent ThreadPoolExecutor workers it is possible for
    this to fire more than once for the same batch under rare timing -
    subscribers should treat batch.complete as idempotent (dedupe on
    batch_id) rather than assuming exactly-once delivery."""
    if not batch_id:
        return

    jobs = AsyncScanJob.query.filter_by(batch_id=batch_id).all()
    if not jobs or any(j.status in ("pending", "running") for j in jobs):
        return

    user_id = jobs[0].user_id
    summary = {
        "batch_id": batch_id,
        "total": len(jobs),
        "complete": sum(1 for j in jobs if j.status == "complete"),
        "failed": sum(1 for j in jobs if j.status == "failed"),
    }
    _dispatch_webhook(user_id, "batch.complete", summary)


''' + old_batch_executor

src = replace_once(src, old_batch_executor, helpers, "helper functions")

# ---------------------------------------------------------------
# 5. Routes: register / list / delete (appended at end of file)
# ---------------------------------------------------------------
routes = '''

@app.route("/api/v1/webhooks", methods=["POST"])
@login_required
def webhook_register():
    data = request.get_json(silent=True) or request.form
    url = (data.get("url") or "").strip()
    event_type = (data.get("event_type") or "all").strip()

    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "url must be a valid http(s) URL"}), 400
    if event_type not in ("job.complete", "batch.complete", "all"):
        return jsonify({"error": "event_type must be job.complete, batch.complete, or all"}), 400

    sub = WebhookSubscription(
        id=str(uuid.uuid4()),
        user_id=session["user_id"],
        url=url,
        secret=secrets.token_hex(32),
        event_type=event_type,
    )
    db.session.add(sub)
    db.session.commit()

    return jsonify({
        "id": sub.id,
        "url": sub.url,
        "secret": sub.secret,  # shown once, at creation only
        "event_type": sub.event_type,
        "is_active": sub.is_active,
    }), 201


@app.route("/api/v1/webhooks", methods=["GET"])
@login_required
def webhook_list():
    subs = WebhookSubscription.query.filter_by(user_id=session["user_id"]).all()
    return jsonify([{
        "id": s.id,
        "url": s.url,
        "event_type": s.event_type,
        "is_active": s.is_active,
        "created_at": s.created_at.isoformat() if s.created_at else None,
        "last_triggered_at": s.last_triggered_at.isoformat() if s.last_triggered_at else None,
        "last_status_code": s.last_status_code,
    } for s in subs])


@app.route("/api/v1/webhooks/<webhook_id>", methods=["DELETE"])
@login_required
def webhook_delete(webhook_id):
    sub = WebhookSubscription.query.filter_by(id=webhook_id, user_id=session["user_id"]).first()
    if not sub:
        return jsonify({"error": "not found"}), 404
    db.session.delete(sub)
    db.session.commit()
    return jsonify({"deleted": True})
'''

src = src.rstrip("\n") + "\n" + routes

# ---------------------------------------------------------------
# Write
# ---------------------------------------------------------------
backup = Path("app.py.bak_webhooks")
shutil.copy(APP_PY, backup)
APP_PY.write_text(src, encoding="utf-8")

print(f"Backed up original -> {backup}")
print("Patched app.py:")
print("  - imports: hmac, hashlib, requests, secrets")
print("  - _dispatch_webhook() + _check_batch_complete() helpers")
print("  - hooked into _run_async_scan success + failure paths")
print("  - routes: POST/GET /api/v1/webhooks, DELETE /api/v1/webhooks/<id>")