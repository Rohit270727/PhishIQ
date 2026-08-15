"""
Adds the batch scan API on top of the existing async job infrastructure:

  POST /api/v1/scan/batch      - submit up to 20 URLs at once, returns
                                  a batch_id and one job_id per URL
  GET  /api/v1/batches/<id>    - aggregate status + each job's result

Uses a single bounded ThreadPoolExecutor (5 workers) for batch dispatch,
separate from the per-URL parallelism inside analyze_url() itself. This
caps total concurrent scans regardless of batch size - without it, a
20-URL batch could spin up 20 threads x the 10-worker pool each scan
already uses internally, i.e. up to 200 threads at once.

The single-URL POST /api/v1/scan/async endpoint is untouched and keeps
using its own raw background thread, as before.

Run this from the PhishIQ project root, after:
    python migrate_add_batch_id.py
    python patch_model_batch_id.py
"""

PATH = "app.py"
MAX_BATCH_SIZE = 20
BATCH_POOL_WORKERS = 5

with open(PATH, "r", encoding="utf-8-sig") as f:
    content = f.read()

original_content = content

# ---------------------------------------------------------------------
# 1. Add a module-level bounded executor for batch dispatch, right
#    after the imports that _run_async_scan/routes already rely on.
#    Anchored on the AsyncScanJob model import line, which is unique.
# ---------------------------------------------------------------------
old = "from models import db, User, ScanHistory, ApiKey, PasswordResetToken, Feedback, AsyncScanJob\n"
if old not in content:
    raise SystemExit("Could not find models import line - has app.py changed?")

new = (
    old
    + "from concurrent.futures import ThreadPoolExecutor\n"
)
content = content.replace(old, new, 1)

# Insert the bounded pool definition right before the async scan route,
# since that's where the existing async infrastructure lives.
old = '@app.route("/api/v1/scan/async", methods=["POST"])'
if old not in content:
    raise SystemExit("Could not find the async scan route - has app.py changed?")

new = (
    f"_batch_executor = ThreadPoolExecutor(max_workers={BATCH_POOL_WORKERS})\n"
    "\n"
    "\n"
    '@app.route("/api/v1/scan/async", methods=["POST"])'
)
content = content.replace(old, new, 1)

# ---------------------------------------------------------------------
# 2. Insert the two batch routes right after api_v1_job_status ends,
#    anchored on the return + blank lines before download_report.
# ---------------------------------------------------------------------
old = (
    "    return jsonify(response)\n"
    "\n"
    "\n"
    '@app.route("/report/<int:scan_id>/download")'
)
if old not in content:
    raise SystemExit("Could not find api_v1_job_status end marker - has app.py changed?")

new_routes = f'''    return jsonify(response)


@app.route("/api/v1/scan/batch", methods=["POST"])
@limiter.limit("10 per minute")
@require_api_key
def api_v1_scan_batch():
    data = request.get_json(force=True, silent=True) or {{}}
    urls = data.get("urls")

    if not isinstance(urls, list) or not urls:
        return jsonify({{"error": "urls must be a non-empty list"}}), 400

    urls = [u.strip() for u in urls if isinstance(u, str) and u.strip()]
    if not urls:
        return jsonify({{"error": "urls must be a non-empty list"}}), 400

    if len(urls) > {MAX_BATCH_SIZE}:
        return jsonify({{"error": f"Batch size exceeds limit of {MAX_BATCH_SIZE} URLs"}}), 400

    batch_id = str(uuid.uuid4())
    job_ids = []

    for url in urls:
        job_id = str(uuid.uuid4())
        job = AsyncScanJob(
            id=job_id,
            user_id=request.api_user_id,
            url=url,
            batch_id=batch_id,
            status="pending",
        )
        db.session.add(job)
        job_ids.append(job_id)

    db.session.commit()

    # Dispatch each job to the bounded batch pool instead of an unbounded
    # raw thread per URL, so a large batch can't spawn unbounded threads.
    for job_id, url in zip(job_ids, urls):
        _batch_executor.submit(_run_async_scan, app, job_id, url, request.api_user_id)

    return jsonify({{
        "batch_id": batch_id,
        "job_ids": job_ids,
        "count": len(job_ids),
        "status": "pending",
    }}), 202


@app.route("/api/v1/batches/<batch_id>", methods=["GET"])
@require_api_key
def api_v1_batch_status(batch_id):
    jobs = AsyncScanJob.query.filter_by(batch_id=batch_id, user_id=request.api_user_id).all()
    if not jobs:
        return jsonify({{"error": "Batch not found"}}), 404

    statuses = {{j.status for j in jobs}}
    if statuses <= {{"complete", "failed"}}:
        overall_status = "complete"
    elif "running" in statuses:
        overall_status = "running"
    else:
        overall_status = "pending"

    job_list = []
    for j in jobs:
        entry = {{"job_id": j.id, "url": j.url, "status": j.status}}
        if j.status == "complete" and j.result:
            entry["result"] = json.loads(j.result)
        elif j.status == "failed" and j.error:
            entry["error"] = j.error
        job_list.append(entry)

    return jsonify({{
        "batch_id": batch_id,
        "status": overall_status,
        "total": len(jobs),
        "complete": sum(1 for j in jobs if j.status == "complete"),
        "failed": sum(1 for j in jobs if j.status == "failed"),
        "jobs": job_list,
    }})


@app.route("/report/<int:scan_id>/download")'''

content = content.replace(old, new_routes, 1)

if content == original_content:
    raise SystemExit("No changes were made - something's wrong, aborting without writing.")

with open(PATH, "w", encoding="utf-8") as f:
    f.write(content)

print("batch API routes added successfully")
