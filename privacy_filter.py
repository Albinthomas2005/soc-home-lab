import ipaddress
import re

EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
IP_RE = re.compile(
    r"(?<![A-Za-z0-9:])"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"(?<![A-Za-z0-9:])"
    r"[0-9A-Fa-f]*:[0-9A-Fa-f:]+"
    r"(?![A-Za-z0-9:])"
)
BEARER_RE = re.compile(
    r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"
)
SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|password|passwd|secret|authorization)"
    r"\b(\s*[:=]\s*)([^\s,;]+)"
)
SENSITIVE_KEYS = re.compile(
    r"(?i)(password|passwd|token|secret|api[_-]?key|"
    r"authorization|credential|private[_-]?key)"
)


def _mask_ip(match):
    value = match.group(0)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value

    if address.is_private or address.is_loopback or address.is_link_local:
        return value
    if not address.is_global:
        return value
    return "[REDACTED_PUBLIC_IP]"


def sanitize_text(value):
    value = EMAIL_RE.sub("[REDACTED_EMAIL]", value)
    value = BEARER_RE.sub("Bearer [REDACTED_TOKEN]", value)
    value = SECRET_RE.sub(
        lambda m: m.group(1) + m.group(2) + "[REDACTED_SECRET]",
        value,
    )
    value = IP_RE.sub(_mask_ip, value)
    return value


def sanitize_alert(value, parent_key=""):
    """Recursively sanitize values in an alert dictionary."""
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if SENSITIVE_KEYS.search(str(key)):
                cleaned[key] = "[REDACTED_SECRET]"
            else:
                cleaned[key] = sanitize_alert(item, str(key))
        return cleaned

    if isinstance(value, list):
        return [sanitize_alert(item, parent_key) for item in value]

    if isinstance(value, str):
        return sanitize_text(value)

    return value
