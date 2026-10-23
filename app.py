import json
import os
from io import BytesIO

from flask import (
    Flask, render_template, request, redirect,
    url_for, make_response
)

from database import init_db, get_alerts, get_raw_alerts, get_raw_alert
from gemini_service import explain_alert, improve_report, GeminiUnavailable

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

init_db()


def ai_is_configured():
    """Check configuration without exposing API key values."""
    return bool(
        os.environ.get("GEMINI_API_KEY")
        or os.environ.get("GOOGLE_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
    )


def get_ai_status():
    if ai_is_configured():
        return (
            "Provider key detected, but AI analysis is not yet connected.",
            False,
        )
    return ("AI unavailable — configure a provider to enable analysis.", False)


@app.route("/")
def dashboard():
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
    high = sum(1 for alert in alerts if alert["severity"] == "High")
    medium = sum(1 for alert in alerts if alert["severity"] == "Medium")
    low = sum(1 for alert in alerts if alert["severity"] == "Low")

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
        explanation = explain_alert(event)
    except GeminiUnavailable as exc:
        return render_template(
            "ai_unavailable.html",
            title="Gemini analysis unavailable",
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
        title="Gemini alert explanation",
        result=explanation,
        alert_id=alert_id,
        result_kind="explanation",
    )


@app.route("/improve-report", methods=["POST"])
def improve_report_route():
    report_text = request.form.get("report_text", "").strip()
    alert_id = request.form.get("alert_id", "").strip()

    if not report_text:
        return render_template(
            "ai_unavailable.html",
            title="Report text required",
            message="Enter rough report notes before requesting improvement.",
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
        ), 400
    except GeminiUnavailable as exc:
        return render_template(
            "ai_unavailable.html",
            title="Gemini report improvement unavailable",
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
    response.headers["Content-Type"] = "text/markdown; charset=utf-8"
    response.headers["Content-Disposition"] = (
        'attachment; filename="soc-incident-report.md"'
    )
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
