"""
End-to-end test for the async scan job flow.

Flow:
  1. POST /api/v1/scan/async  -> get job_id
  2. Poll GET /api/v1/jobs/<job_id> until status is complete/failed
  3. POST /api/v1/scan (sync) with the same URL
  4. Diff score/verdict/flags between the async result and the sync result

Requires the Flask app to be running (e.g. `python app.py`) in another terminal.
"""

import time
import sys
import requests

BASE_URL = "http://127.0.0.1:5050"   # change port here if your app runs elsewhere
API_KEY = "783736e154d89da8e5d0fbdbe431b3aeb55f6f7cd988c2da922f3adf719d8bf4"
TEST_URL = "http://paypal-secure-login.verify-account.tk/reset"  # a suspicious-looking test URL

HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

POLL_INTERVAL_SEC = 1
POLL_TIMEOUT_SEC = 60


def fail(msg):
    print(f"\nFAIL: {msg}")
    sys.exit(1)


def main():
    print(f"Base URL: {BASE_URL}")
    print(f"Test URL: {TEST_URL}\n")

    # 1. Submit async job
    print("1. Submitting async scan job...")
    resp = requests.post(f"{BASE_URL}/api/v1/scan/async", headers=HEADERS, json={"url": TEST_URL})
    if resp.status_code != 200 and resp.status_code != 201 and resp.status_code != 202:
        fail(f"Unexpected status {resp.status_code} from /api/v1/scan/async: {resp.text}")

    data = resp.json()
    job_id = data.get("job_id")
    if not job_id:
        fail(f"No job_id in response: {data}")
    print(f"   job_id = {job_id}")
    print(f"   initial status = {data.get('status')}")

    # 2. Poll for completion
    print("\n2. Polling job status...")
    start = time.time()
    final_job = None
    while time.time() - start < POLL_TIMEOUT_SEC:
        resp = requests.get(f"{BASE_URL}/api/v1/jobs/{job_id}", headers=HEADERS)
        if resp.status_code != 200:
            fail(f"Unexpected status {resp.status_code} from /api/v1/jobs/{job_id}: {resp.text}")
        job = resp.json()
        print(f"   status = {job.get('status')}")
        if job.get("status") in ("complete", "failed"):
            final_job = job
            break
        time.sleep(POLL_INTERVAL_SEC)

    if final_job is None:
        fail(f"Job did not complete within {POLL_TIMEOUT_SEC}s")

    if final_job.get("status") == "failed":
        fail(f"Job failed: {final_job.get('error')}")

    async_result = final_job.get("result")
    if not async_result:
        fail(f"Job marked complete but no 'result' field: {final_job}")

    print(f"\n   Async result: score={async_result.get('score')} verdict={async_result.get('verdict')} "
          f"flags={len(async_result.get('flags', []))}")

    # 3. Call sync endpoint with the same URL
    print("\n3. Calling sync /api/v1/scan for comparison...")
    resp = requests.post(f"{BASE_URL}/api/v1/scan", headers=HEADERS, json={"url": TEST_URL})
    if resp.status_code != 200:
        fail(f"Unexpected status {resp.status_code} from /api/v1/scan: {resp.text}")
    sync_result = resp.json()
    print(f"   Sync result:  score={sync_result.get('score')} verdict={sync_result.get('verdict')} "
          f"flags={len(sync_result.get('flags', []))}")

    # 4. Diff
    print("\n4. Comparing async vs sync results...")
    mismatches = []

    if async_result.get("score") != sync_result.get("score"):
        mismatches.append(f"score: async={async_result.get('score')} sync={sync_result.get('score')}")

    if async_result.get("verdict") != sync_result.get("verdict"):
        mismatches.append(f"verdict: async={async_result.get('verdict')} sync={sync_result.get('verdict')}")

    async_reasons = sorted(f.get("reason") for f in async_result.get("flags", []))
    sync_reasons = sorted(f.get("reason") for f in sync_result.get("flags", []))
    if async_reasons != sync_reasons:
        mismatches.append(f"flags: async={async_reasons} sync={sync_reasons}")

    if mismatches:
        fail("Results differ:\n   " + "\n   ".join(mismatches))

    print("\nPASS: async job flow works end-to-end and matches the sync endpoint.")


if __name__ == "__main__":
    main()