# SOC AI Alert Analyzer

An educational SOC home lab using Wazuh, Python, Groq, privacy filtering, and OpenSearch.

## Workflow

1. Receive or select a Wazuh-style security alert.
2. Sanitize selected sensitive values before external AI analysis.
3. Generate an AI-assisted explanation for analyst review.
4. Store the explanation and sanitized alert in a dedicated OpenSearch index.
5. Review stored results and validate findings manually.

## Features

- Synthetic-alert analysis with Groq
- Privacy-filtering helpers and unit tests
- OpenSearch indexing over HTTPS
- Separate reader and writer role examples
- Initial Wazuh alert importer and SQLite storage
- GitHub Actions workflow for Python unit tests

## Requirements

- Python 3.10 or newer
- Access to a Groq API key for AI analysis
- OpenSearch configured for the integration test
- Wazuh is needed for the full SIEM lab, but basic unit tests can run without a Wazuh server

## Local setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` locally and set your own `GROQ_API_KEY`. Never commit the real `.env` file. OpenSearch connection settings and credentials must be configured locally according to your deployment and the integration script.

## Internal AI analysis API

The local Flask service provides `POST /api/ai/analyze-alert` for trusted
services that need an AI explanation. It requires a bearer token in the
`SOC_AI_INTERNAL_TOKEN` environment variable, accepts a JSON object containing
an `alert` object, sanitizes the alert before analysis, and returns JSON. The
endpoint shares the app's 1 MiB request-size limit and is not intended for
public exposure. The included Flask runner binds to `127.0.0.1`.

The trusted Wazuh Dashboard server can also call
`POST /api/ai/generate-report`. It requires the same bearer token and accepts a
selected record reference, a minimized alert, and optional analyst context.
The JSON request fields are `evidence.index`, `evidence.id`,
`evidence.alert`, and optional `analyst_notes`, for example:

```json
{
  "evidence": {
    "index": "wazuh-alerts-4.x-2026.10.25",
    "id": "<selected-document-id>",
    "alert": {"rule": {"id": "1001"}}
  },
  "analyst_notes": "Optional context from the analyst"
}
```

Requests are limited to 256 KiB and notes to 4,000 characters. The index must
match `wazuh-alerts-4.x-*` and document IDs are limited to 512 UTF-8 bytes.
The Wazuh controller retrieves the record as the signed-in user before making
this request; browser-supplied alert contents are not used as evidence. The
backend re-applies an evidence allowlist and privacy filtering before sending
the request to Groq. Report drafts are labeled AI-generated and unverified,
are not saved by this endpoint, and do not include related-log searches.
Analyst-edited Markdown export is performed in the dashboard browser; keep the
exported file in an approved case-management location if it must be retained.
The legacy `/explain`, `/improve-report`, and `/export-report` form routes are
not used by this dashboard workflow and do not have application-level
authentication. Keep the backend loopback-only unless those routes are secured
separately; the active service binding could not be verified from this
development environment.

Generate a strong token locally with:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Set the generated value as `SOC_AI_INTERNAL_TOKEN` in the ignored local `.env`
file (or the service's protected environment configuration). Configure the
same value securely in any trusted caller. Do not commit, log, or share the
token. Keep `.env.example` as a placeholder only.

## Run tests

```bash
python -m unittest discover -s tests -v
```

GitHub Actions runs the same unit-test command on pushes and pull requests to `main`.

## Synthetic alert integration test

After configuring the Groq API key, OpenSearch URL, TLS certificate, and least-privilege OpenSearch credentials for your local environment, run:

```bash
python3 wazuh_groq_integration.py synthetic_alert.json
```

Do not run this integration test until the local OpenSearch settings are configured and you have confirmed the target index and credentials.

## Security notes

- Never commit API keys, passwords, private keys, databases, or real security logs.
- The privacy filter covers selected patterns; it does not guarantee complete anonymization.
- Review alerts and sanitized output before sending data to an external AI provider.
- AI-generated explanations can be incorrect. A human analyst must verify them before taking action.
- Use synthetic alerts for demonstrations until privacy controls have been validated against your own data.

## Project status

The repository includes the synthetic-alert integration, OpenSearch role examples, importer, and privacy-filter tests. Previous local testing reported eight privacy-filter tests passing and a synthetic explanation successfully stored in OpenSearch. The GitHub Actions run and a clean-machine setup still need to be checked. Automated processing of selected real alerts is not yet considered production-ready.

## Author

Albin Thomas — Cybersecurity and SOC Analyst Learning
