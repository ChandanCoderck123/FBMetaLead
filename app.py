import hmac
import hashlib
import json
from datetime import datetime, timezone
import requests
from flask import Flask, request, abort, jsonify
from sqlalchemy import create_engine, text
from sqlalchemy.pool import QueuePool

# --- Config from environment variables (hardcoded for this example) ---
VERIFY_TOKEN = "VERIFY_TOKEN"
APP_SECRET = b"e4a23c213b6765ab31dc5c4b217b64c9"  # bytes for HMAC
PAGE_ACCESS_TOKEN = "EAASmzt8imZAsBPoKbH7AP9ab7O4AbfB8yR2vgNZBmDgae8ripSewpMA8V12mkfDHezEZCZAyUduKNgX8gRZAcUGZAvsNMzmOgr2bP7pC6f3OFmZAfvlzAiy7biZB1L0ECZCE2hiy7uKwpkaql1HmF9zMU1ZA7cUXHkHZBU5HLIgZAoX9LTDZB7HwoZB6lyFCPBPcSe"
DATABASE_URL = "postgresql+psycopg2://qispineadmin:TrOpSnl1H1QdKAFsAWnY@qispine-db.cqjl02ffrczp.ap-south-1.rds.amazonaws.com:5432/qed_prod"
GRAPH_VERSION = "v23.0"  # Graph API version

# --- DB connection setup ---
engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool, pool_size=5, max_overflow=5, pool_pre_ping=True
)

# --- Flask setup ---
app = Flask(__name__)

def make_appsecret_proof(token: str) -> str:
    """
    Meta recommends appsecret_proof: HMAC-SHA256 of access token using app secret.
    Attach as &appsecret_proof=... to Graph requests.
    """
    digest = hmac.new(APP_SECRET, msg=token.encode("utf-8"), digestmod=hashlib.sha256).hexdigest()
    return digest

def verify_signature(request) -> None:
    """
    Validate X-Hub-Signature-256 header to ensure the payload is from Meta.
    Aborts 403 if signature mismatch.
    """
    sig_header = request.headers.get("X-Hub-Signature-256", "")
    if not sig_header.startswith("sha256="):
        abort(403)
    sent_sig = sig_header.split("=", 1)[1]
    raw = request.get_data()  # exact bytes Meta signed
    expected_sig = hmac.new(APP_SECRET, raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sent_sig, expected_sig):
        abort(403)

@app.get("/webhook")
def verify_webhook():
    """
    Meta sends GET request with hub.mode, hub.challenge, and hub.verify_token.
    Verify token and echo back hub.challenge to complete the handshake.
    """
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")
    if mode == "subscribe" and token == VERIFY_TOKEN and challenge:
        return challenge, 200
    return "Forbidden", 403

@app.post("/webhook")
def receive_webhook():
    """
    Meta sends leadgen event notifications via POST.
    - Validate signature
    - Save the lead data to Postgres
    """
    verify_signature(request)  # Security check

    payload = request.get_json(silent=True) or {}
    if payload.get("object") != "page":
        return "ignored", 200

    # Iterate over batched entries/changes
    for entry in payload.get("entry", []):
        for change in entry.get("changes", []):
            if change.get("field") != "leadgen":
                continue

            v = change.get("value", {})
            leadgen_id   = str(v.get("leadgen_id"))
            page_id      = str(v.get("page_id"))
            form_id      = str(v.get("form_id"))
            ad_id        = str(v.get("ad_id"))
            adset_id     = str(v.get("adgroup_id"))
            created_ts   = v.get("created_time")  # unix seconds

            # Fetch full lead details using the leadgen_id
            params = {
                "access_token": PAGE_ACCESS_TOKEN,
                "appsecret_proof": make_appsecret_proof(PAGE_ACCESS_TOKEN),
            }
            url = f"https://graph.facebook.com/{GRAPH_VERSION}/{leadgen_id}"
            resp = requests.get(url, params=params, timeout=10)
            resp.raise_for_status()
            lead_json = resp.json()

            # Transform field_data -> flat dict {"field_name": "value"}
            answers = {}
            for item in lead_json.get("field_data", []):
                name = item.get("name")
                values = item.get("values") or []
                answers[name] = values[0] if values else None

            # Convert unix seconds to UTC
            created_dt = None
            if isinstance(created_ts, (int, float)):
                created_dt = datetime.fromtimestamp(created_ts, tz=timezone.utc)

            # UPSERT lead data (ignores duplicates by leadgen_id)
            with engine.begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO ch_fb_leads
                        (lead_id, page_id, form_id, ad_id, adset_id, campaign_id, created_time_utc,
                         field_data, raw_payload)
                        VALUES
                        (:lead_id, :page_id, :form_id, :ad_id, :adset_id, :campaign_id, :created_time_utc,
                         CAST(:field_data AS JSONB), CAST(:raw_payload AS JSONB))
                        ON CONFLICT (lead_id) DO NOTHING
                    """),
                    dict(
                        lead_id=leadgen_id,
                        page_id=page_id,
                        form_id=form_id,
                        ad_id=ad_id,
                        adset_id=adset_id,
                        campaign_id=v.get("campaign_id", ""),
                        created_time_utc=created_dt,
                        field_data=json.dumps(answers),
                        raw_payload=json.dumps(change),
                    )
                )

    return "ok", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)

