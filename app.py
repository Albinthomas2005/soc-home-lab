
import hmac
import json
import os

from dotenv import load_dotenv
from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    make_response,
)

from database import (
    init_db,
    get_alerts,
    get_raw_alerts,
    get_raw_alert,
)
from gemini_service import (
    explain_alert,
    improve_report,
    GeminiUnavailable,
)
from privacy_filter import sanitize_alert

# Load environment variables from the local .env file.
load_dotenv()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024


@app.errorhandler(413)
def handle_request_too_large(error):
    if request.path == "/api/ai/analyze-alert":
        return jsonify(
            ok=False,
            error="Request body is too large",
        ), 413
    return error

# Initialize the local database.
init_db()


def ai_is_configured():
    """Check whether a Groq API key is configured."""
    return bool(os.environ.get("GROQ_API_KEY"))


def get_ai_status():
    """Return the AI configuration status without exposing secrets."""
    if ai_is_configured():
        return (
            "Groq API key detected; connection has not yet been tested.",
            True,
        )

    return (
        "AI unavailable — configure GROQ_API_KEY in .env.",
        False,
    )


@app.route("/")
def dashboard():
    from flask import redirect
    return redirect("https://localhost/", code=302)

    alerts = get_alerts()
    raw_alerts = get_raw_alerts(limit=100)

    selected_id = request.args.get("alert_id")
    selected = get_raw_alert(selected_id) if selected_id else None

    # Default to the newest raw event when no selection is provided.
    if selected is None and raw_alerts:
        selected = raw_alerts[0]

    original_event = None

    if selected:
        try:
            original_event = json.loads(selected["raw_json"])
        except (TypeError, json.JSONDecodeError):
            original_event = None

    total = len(alerts)
    high = sum(
        1 for alert in alerts if alert["severity"] == "High"
    )
    medium = sum(
        1 for alert in alerts if alert["severity"] == "Medium"
    )
    low = sum(
        1 for alert in alerts if alert["severity"] == "Low"
    )

    ai_status, ai_ready = get_ai_status()

    return render_template(
        "dashboard.html",
        alerts=alerts,
        raw_alerts=raw_alerts,
        selected=selected,
        original_event=original_event,
        ai_status=ai_status,
        ai_ready=ai_ready,
        total=total,
        high=high,
        medium=medium,
        low=low,
        explanation=None,
        report_output=None,
        report_input="",
    )


@app.route("/explain", methods=["POST"])
def explain_alert_route():
    alert_id = request.form.get("alert_id", "").strip()
    selected = get_raw_alert(alert_id) if alert_id else None

    if not selected:
        return render_template(
            "ai_unavailable.html",
            title="Alert not found",
            message="The selected Wazuh alert could not be found.",
            alert_id=alert_id,
        ), 404

    try:
        event = json.loads(selected["raw_json"])
        safe_event = sanitize_alert(event)
        explanation = explain_alert(safe_event)

    except GeminiUnavailable as exc:
        return render_template(
            "ai_unavailable.html",
            title="Groq analysis unavailable",
            message=str(exc),
            alert_id=alert_id,
        ), 503

    except (TypeError, json.JSONDecodeError):
        return render_template(
            "ai_unavailable.html",
            title="Alert data error",
            message="The stored alert JSON could not be parsed.",
            alert_id=alert_id,
        ), 500

    return render_template(
        "ai_result.html",
        title="Groq alert explanation",
        result=explanation,
        alert_id=alert_id,
        result_kind="explanation",
    )


@app.route("/api/ai/analyze-alert", methods=["POST"])
def analyze_alert_api():
    expected_token = os.environ.get("SOC_AI_INTERNAL_TOKEN", "")
    authorization = request.headers.get("Authorization", "")
    scheme, separator, supplied_token = authorization.partition(" ")

    if (
        not expected_token
        or not separator
        or scheme.lower() != "bearer"
        or not supplied_token
        or not hmac.compare_digest(
            supplied_token.encode("utf-8"),
            expected_token.encode("utf-8"),
        )
    ):
        return jsonify(ok=False, error="Authentication required"), 401

    if not request.is_json:
        return jsonify(ok=False, error="A JSON alert is required"), 400

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(ok=False, error="A JSON alert is required"), 400

    alert = payload.get("alert")
    if not isinstance(alert, dict) or not alert:
        return jsonify(ok=False, error="A valid alert object is required"), 400

    try:
        safe_alert = sanitize_alert(alert)
        analysis = explain_alert(safe_alert)
    except GeminiUnavailable:
        return jsonify(
            ok=False,
            error="AI analysis is temporarily unavailable",
        ), 503
    except Exception:
        return jsonify(
            ok=False,
            error="AI analysis could not be completed",
        ), 500

    return jsonify(ok=True, analysis=analysis)


@app.route("/improve-report", methods=["POST"])
def improve_report_route():
    report_text = request.form.get("report_text", "").strip()
    alert_id = request.form.get("alert_id", "").strip()

    if not report_text:
        return render_template(
            "ai_unavailable.html",
            title="Report text required",
            message=(
                "Enter rough report notes before "
                "requesting improvement."
            ),
            alert_id=alert_id,
        ), 400

    try:
        improved = improve_report(report_text)

    except ValueError as exc:
        return render_template(
            "ai_unavailable.html",
            title="Report text required",
            message=str(exc),
            alert_id=alert_id,
            report_text=report_text,
        ), 400

    except GeminiUnavailable as exc:
        return render_template(
            "ai_unavailable.html",
            title="Groq report improvement unavailable",
            message=str(exc),
            alert_id=alert_id,
            report_text=report_text,
        ), 503

    return render_template(
        "ai_result.html",
        title="Improved incident report",
        result=improved,
        alert_id=alert_id,
        result_kind="report",
    )


@app.route("/export-report", methods=["POST"])
def export_report():
    report_text = request.form.get("report_text", "").strip()

    if not report_text:
        return "No report text was provided.", 400

    response = make_response(report_text + "\n")
    response.headers["Content-Type"] = (
        "text/markdown; charset=utf-8"
    )
    response.headers["Content-Disposition"] = (
        'attachment; filename="soc-incident-report.md"'
    )

    return response


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
