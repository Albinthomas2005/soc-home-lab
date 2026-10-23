# SOC AI Alert Analyzer

An AI-assisted SOC home lab using Wazuh, Groq, Python, and OpenSearch.

## Overview
This educational project explores AI-assisted security alert analysis.
It sanitizes selected alert data, generates explanations through Groq,
and stores results in OpenSearch for review.

## Features
- Synthetic-alert analysis with Groq
- Privacy filtering for selected sensitive values
- OpenSearch indexing over HTTPS
- Separate reader and writer accounts
- Python unit tests for privacy filtering
- Initial Wazuh alert importer and SQLite storage

## Technology
Python, Wazuh, Groq API, OpenSearch, Ubuntu Linux, JSON, SQLite.

## Run tests
```bash
python3 -m unittest discover -s tests -v
```

## Synthetic alert test
Configure credentials, dependencies, TLS, and OpenSearch permissions first:
```bash
python3 wazuh_groq_integration.py synthetic_alert.json
```

## Security
Never commit API keys, passwords, private keys, databases, or real security logs.
The privacy filter covers selected patterns; it does not guarantee complete
redaction. Review alerts before sending them to external AI services.
AI-generated explanations require human verification.

## Status
Synthetic alert processing, OpenSearch storage, reader permissions, and eight
basic privacy-filter tests have been verified. Automated processing of selected
real alerts and full end-to-end validation remain in development.

## Author
Albin Thomas — Cybersecurity and SOC Analyst Learning
