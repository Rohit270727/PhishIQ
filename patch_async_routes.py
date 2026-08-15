path = "app.py"
with open(path, encoding="utf-8-sig") as f:
    content = f.read()

# 1. Add uuid and threading imports near the top, after the json/re/secrets imports.
old_imports = "import json\nimport re\nimport secrets\n"
new_imports = old_imports + "import uuid\nimport threading\n"
assert content.count(old_imports) == 1, "import anchor not found or not unique"
content = content.replace(old_imports, new_imports)

# 2. Add AsyncScanJob to the models import line.
old_models_import = "from models import db, User, ScanHistory, ApiKey, PasswordResetToken, Feedback"
new_models_import = old_models_import + ", AsyncScanJob"
assert content.count(old_models_import) == 1, "models import anchor not found or not unique"
content = content.replace(old_models_import, new_models_import)

# 3. Insert the two new routes right after the existing /api/v1/scan route.
old_anchor = (
    '    return jsonify({\n'
    '        "url": url,\n'
    '        "score": result["score"],\n'
    '        "verdict": result["verdict"],\n'
    '        "flags": [{"reason": r, "points": p} for r, p in result["flags"]]\n'
    '    })\n'
)
assert content.count(old_anchor) == 1, "api_v1_scan return anchor not found or not unique"

new_routes = old_anchor + '''

def _run_async_scan(app_instance, job_id, url, user_id):
    """Runs analyze_url() in a background thread and updates the
    AsyncScanJob row with the result. Needs an explicit app context
    since this executes outside the original request."""
    with app_instance.app_context():
        job = AsyncScanJob.query.get(job_id)
        if not job:
            return
        job.status = "running"
        db.session.commit()

        try:
            result = analyze_url(url)

            scan = ScanHistory(
                user_id=user_id,
                scan_type="url",
                input_data=url,
                risk_score=result["score"],
                verdict=result["verdict"],
                flags=json.dumps(result["flags"])
            )
            db.session.add(scan)

            job.status = "complete"
            job.result = json.dumps({
                "url": url,
                "score": result["score"],
                "verdict": result["verdict"],
                "flags": [{"reason": r, "points": p} for r, p in result["flags"]]
            })
            job.completed_at = datetime.utcnow()
            db.session.commit()
        except Exception as e:
            job.status = "failed"
            job.error = str(e)
            job.completed_at = datetime.utcnow()
            db.session.commit()


@csrf.exempt
@app.route("/api/v1/scan/async", methods=["POST"])
@limiter.limit("30 per minute")
@require_api_key
def api_v1_scan_async():
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400

    job_id = str(uuid.uuid4())
    job = AsyncScanJob(id=job_id, user_id=request.api_user_id, url=url, status="pending")
    db.session.add(job)
    db.session.commit()

    thread = threading.Thread(
        target=_run_async_scan,
        args=(app, job_id, url, request.api_user_id),
        daemon=True
    )
    thread.start()

    return jsonify({"job_id": job_id, "status": "pending"}), 202


@app.route("/api/v1/jobs/<job_id>", methods=["GET"])
@require_api_key
def api_v1_job_status(job_id):
    job = AsyncScanJob.query.filter_by(id=job_id, user_id=request.api_user_id).first()
    if not job:
        return jsonify({"error": "Job not found"}), 404

    response = {"job_id": job.id, "status": job.status}
    if job.status == "complete" and job.result:
        response["result"] = json.loads(job.result)
    elif job.status == "failed" and job.error:
        response["error"] = job.error

    return jsonify(response)
'''

content = content.replace(old_anchor, new_routes)

with open(path, "w", encoding="utf-8", newline="") as f:
    f.write(content)

print("async job routes added successfully")
