# app.py
# --------------------------------------------------------------------
# Facebook Lead Ads → Webhook → Save to Postgres (real-time)
# Matches your table: ch_fb_leads
# --------------------------------------------------------------------

import json
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests
from flask import Flask, request, abort, jsonify
import psycopg2
import psycopg2.extras

# ------------------------------ CONFIG ------------------------------
# Fill these values directly (no .env as requested).
VERIFY_TOKEN = "VERIFY_TOKEN"         # Used only for GET verification
APP_SECRET   = b"e4a23c213b6765ab31dc5c4b217b64c9"          # Meta App Secret (bytes!)
PAGE_ACCESS_TOKEN = "EAASmzt8imZAsBPoKbH7AP9ab7O4AbfB8yR2vgNZBmDgae8ripSewpMA8V12mkfDHezEZCZAyUduKNgX8gRZAcUGZAvsNMzmOgr2bP7pC6f3OFmZAfvlzAiy7biZB1L0ECZCE2hiy7uKwpkaql1HmF9zMU1ZA7cUXHkHZBU5HLIgZAoX9LTDZB7HwoZB6lyFCPBPcSe"    # Page token with leads_retrieval

# Postgres connection (RDS/EC2) - direct values
PG_HOST = "qispine-db.cqjl02ffrczp.ap-south-1.rds.amazonaws.com"
PG_PORT = 5432
PG_DB   = "qed_prod"
PG_USER = "qispineadmin"
PG_PASS = "TrOpSnl1H1QdKAFsAWnY"

# Graph API version
GRAPH_VERSION = "v23.0"
# --------------------------------------------------------------------


app = Flask(__name__)


# -------------------------- DB UTILITIES ----------------------------
def get_conn():
    """Open a fresh Postgres connection; callers must close()."""
    return psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER, password=PG_PASS
    )


def upsert_lead_row(
    lead_id: str,
    page_id: Optional[str],
    form_id: Optional[str],
    ad_id: Optional[str],
    adset_id: Optional[str],
    campaign_id: Optional[str],
    created_time_utc: Optional[datetime],
    field_data_json: Dict[str, Any],
    raw_payload_json: Dict[str, Any],
):
    """
    Insert or update a row into ch_fb_leads using ON CONFLICT (lead_id).
    """
    sql = """
    INSERT INTO ch_fb_leads
      (lead_id, page_id, form_id, ad_id, adset_id, campaign_id, created_time_utc, field_data, raw_payload)
    VALUES
      (%(lead_id)s, %(page_id)s, %(form_id)s, %(ad_id)s, %(adset_id)s, %(campaign_id)s, %(created_time_utc)s, %(field_data)s, %(raw_payload)s)
    ON CONFLICT (lead_id) DO UPDATE SET
      page_id = EXCLUDED.page_id,
      form_id = EXCLUDED.form_id,
      ad_id = EXCLUDED.ad_id,
      adset_id = EXCLUDED.adset_id,
      campaign_id = EXCLUDED.campaign_id,
      created_time_utc = EXCLUDED.created_time_utc,
      field_data = EXCLUDED.field_data,
      raw_payload = EXCLUDED.raw_payload;
    """
    params = {
        "lead_id": lead_id,
        "page_id": page_id,
        "form_id": form_id,
        "ad_id": ad_id,
        "adset_id": adset_id,
        "campaign_id": campaign_id,
        "created_time_utc": created_time_utc,
        "field_data": json.dumps(field_data_json) if field_data_json is not None else None,
        "raw_payload": json.dumps(raw_payload_json) if raw_payload_json is not None else None,
    }

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


# -------------------------- FB API HELPERS --------------------------
def parse_fb_timestamp(ts: Any) -> Optional[datetime]:
    """
    Accepts either an epoch (int/str) or ISO 8601 string; returns aware UTC datetime.
    """
    if ts is None:
        return None
    try:
        # Epoch (sometimes change.value.created_time is epoch seconds)
        if isinstance(ts, (int, float)) or (isinstance(ts, str) and ts.isdigit()):
            return datetime.fromtimestamp(int(ts), tz=timezone.utc)
        # ISO string
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def fetch_full_lead(leadgen_id: str) -> Dict[str, Any]:
    """
    Fetch full lead details by leadgen_id. Includes field_data, ad/form/page IDs, and created_time.
    """
    url = f"https://graph.facebook.com/{GRAPH_VERSION}/{leadgen_id}"
    params = {"access_token": PAGE_ACCESS_TOKEN}
    resp = requests.get(url, params=params, timeout=20)
    resp.raise_for_status()
    return resp.json()


def fetch_campaign_from_ad(ad_id: str) -> Optional[str]:
    """
    (Optional) Try to map ad_id -> campaign_id. Not strictly required.
    If the token lacks permission, we quietly return None.
    """
    if not ad_id:
        return None
    try:
        url = f"https://graph.facebook.com/{GRAPH_VERSION}/{ad_id}"
        params = {"fields": "campaign_id", "access_token": PAGE_ACCESS_TOKEN}
        r = requests.get(url, params=params, timeout=15)
        if r.status_code == 200:
            data = r.json()
            return data.get("campaign_id")
    except Exception:
        pass
    return None


# ------------------------- SECURITY: SIGNATURE -----------------------
def good_signature(raw_body: bytes, signature_header: Optional[str]) -> bool:
    """
    Validate X-Hub-Signature-256 header: 'sha256=<hex>'.
    """
    if not signature_header:
        return False
    if "=" not in signature_header:
        return False
    algo, their_sig = signature_header.split("=", 1)
    if algo.lower() != "sha256":
        return False
    mac = hmac.new(APP_SECRET, msg=raw_body, digestmod=hashlib.sha256)
    my_sig = mac.hexdigest()
    return hmac.compare_digest(my_sig, their_sig)


# ---------------------- WEBHOOK ENDPOINTS ---------------------------
@app.get("/webhook")
def verify_webhook():
    """
    Meta will call this once when you add the callback URL.
    We must echo back hub.challenge if the verify token matches.
    """
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == VERIFY_TOKEN:
        return challenge, 200
    return "Verification failed", 403


@app.post("/webhook")
def receive_webhook():
    """
    Receive real-time leadgen events. Validate signature, parse events,
    fetch the full lead, and upsert into Postgres.
    """
    # 1) Validate signature
    sig256 = request.headers.get("X-Hub-Signature-256")
    if not good_signature(request.data, sig256):
        abort(403)

    # 2) Parse payload
    payload = request.get_json(silent=True) or {}
    # Save the raw payload for traceability
    raw_payload_json = payload

    # 3) Iterate entries/changes (Meta batches events)
    for entry in payload.get("entry", []):
        for change in entry.get("changes", []):
            value = change.get("value", {})
            # leadgen_id is the key we need to fetch full details
            lead_id = value.get("leadgen_id")
            page_id = value.get("page_id")  # helpful but we’ll also take from the fetched lead

            if not lead_id:
                # If a non-lead change came through, just skip
                continue

            # 4) Fetch full lead by ID (includes field_data, form_id, ad_id, created_time, page_id)
            try:
                lead = fetch_full_lead(lead_id)
            except Exception as e:
                # If fetching fails (e.g., transient token error), skip but return 200
                # so FB won't retry forever. Consider alerting/logging.
                print(f"[WARN] fetch_full_lead failed for {lead_id}: {e}")
                continue

            # 5) Extract fields we care about
            form_id   = lead.get("form_id")
            ad_id     = lead.get("ad_id")
            adset_id  = lead.get("adset_id")
            page_id   = lead.get("page_id") or page_id
            created_time_utc = parse_fb_timestamp(lead.get("created_time"))

            # Field data is typically an array of {name, values:[...]} — store raw
            field_data = lead.get("field_data") or {}

            # 6) (Optional) Try to get campaign_id from ad_id
            campaign_id = fetch_campaign_from_ad(ad_id) if ad_id else None

            # 7) Upsert into DB (idempotent on lead_id)
            try:
                upsert_lead_row(
                    lead_id=lead_id,
                    page_id=page_id,
                    form_id=form_id,
                    ad_id=ad_id,
                    adset_id=adset_id,
                    campaign_id=campaign_id,
                    created_time_utc=created_time_utc,
                    field_data_json=field_data,
                    raw_payload_json=raw_payload_json,
                )
            except Exception as e:
                # If DB write fails, still return 200 so FB doesn’t back off;
                # You can add your own alerting here.
                print(f"[ERROR] DB upsert failed for {lead_id}: {e}")

    # 8) Always 200 quickly; Meta expects this within ~10 seconds
    return jsonify({"status": "ok"}), 200


# ------------------------- APP ENTRYPOINT ---------------------------
if __name__ == "__main__":
    # For dev only. In production, use gunicorn (shown below).
    app.run(host="0.0.0.0", port=5000)
