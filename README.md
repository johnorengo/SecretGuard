# SecretGuard

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Build Passing](https://img.shields.io/badge/build-passing-brightgreen)
![Security Tool](https://img.shields.io/badge/security-tool-red)

SecretGuard is a lightweight DevSecOps security tool that helps developers prevent accidental exposure of credentials by scanning repositories for sensitive information before deployment.

It is designed for teams that want a simple, readable, open-source command line scanner that can run locally before code reaches GitHub, CI, or production.

## Features

- ✔ Repository scanning
- ✔ API key detection
- ✔ Password detection
- ✔ Cloud secret detection
- ✔ JSON reports
- ✔ Developer friendly CLI

## Why SecretGuard?

Leaked credentials can expose cloud accounts, databases, internal systems, and customer data. SecretGuard helps developers catch risky secrets early, improve secure coding habits, and support practical DevSecOps workflows without adding heavy tooling.

## Installation

```bash
git clone https://github.com/example/secretguard.git
cd secretguard
pip install .
```

For development:

```bash
pip install -r requirements.txt
pip install -e .
pytest
```

## Quick Start

```bash
secretguard scan ./my-project
```

Generate a JSON report:

```bash
secretguard scan ./my-project --json
```

## Example Output

```text
================================
SecretGuard Security Scan

Files scanned: 247
Secrets Found: 3
Security Status: HIGH RISK
================================

Findings:

[HIGH]
AWS Access Key Found

File:
config/settings.py

Line:
27

Recommendation:
Remove secret and rotate credential
```

## JSON Reports

Use `--json` to generate `reports/security-report.json`.

```json
{
  "scan_date": "2026-07-07T12:00:00+00:00",
  "files_scanned": 247,
  "total_findings": 3,
  "risk_level": "HIGH RISK",
  "findings": []
}
```

Each finding includes the rule name, severity, file path, line number, recommendation, and a masked secret value to reduce accidental exposure in reports.

## Supported Secret Detection

| Secret Type | Severity |
| --- | --- |
| AWS Access Keys | HIGH |
| AWS Secret Keys | CRITICAL |
| Google API Keys | HIGH |
| GitHub Tokens | CRITICAL |
| JWT Tokens | MEDIUM |
| Database credentials | HIGH |
| MongoDB connection strings | HIGH |
| MySQL credentials | HIGH |
| PostgreSQL credentials | HIGH |
| Private keys | CRITICAL |
| Password variables | MEDIUM |
| API tokens | HIGH |
| Environment secrets | MEDIUM |

## Project Architecture

```text
secretguard/
├── secretguard/
│   ├── __init__.py
│   ├── scanner.py
│   ├── detector.py
│   ├── reporter.py
│   ├── cli.py
│   ├── config.py
│   └── utils.py
├── rules/
│   └── patterns.json
├── reports/
├── tests/
├── examples/
├── docs/
├── README.md
├── requirements.txt
├── setup.py
├── pyproject.toml
├── .gitignore
└── LICENSE
```

The scanner walks repositories safely, the detector applies JSON-backed regex rules, and the reporter renders both terminal and machine-readable output.

## Screenshots

Add screenshots or terminal captures here:

```text
docs/images/demo.png
```

## Security Recommendations

When SecretGuard finds a secret:

- Remove the secret from source code
- Rotate the exposed credential with the provider
- Use environment variables or a secret manager
- Review audit logs for suspicious activity
- Avoid committing real `.env` files

## Future Improvements

- GitHub Actions integration
- Pre commit hook
- Web dashboard
- AI risk analysis
- Docker support

## Contributing

Contributions are welcome. Good first issues include adding new detection rules, improving tests, enhancing documentation, and integrating SecretGuard into common developer workflows.

1. Fork the repository
2. Create a feature branch
3. Add tests for your change
4. Run `pytest`
5. Open a pull request

## License

SecretGuard is released under the MIT License. See [LICENSE](LICENSE) for details.
