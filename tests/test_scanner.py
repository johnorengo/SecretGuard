import json

from secretguard.reporter import write_json_report
from secretguard.scanner import RepositoryScanner


def test_scanner_counts_files_and_findings(tmp_path) -> None:
    safe_file = tmp_path / "safe.py"
    safe_file.write_text("print('hello')", encoding="utf-8")
    vulnerable_file = tmp_path / "config.py"
    vulnerable_file.write_text("GITHUB_TOKEN='ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD'", encoding="utf-8")

    result = RepositoryScanner().scan(tmp_path)

    assert result.files_scanned == 2
    assert result.total_findings == 1
    assert result.risk_level == "CRITICAL RISK"


def test_scanner_ignores_directories_and_env_example(tmp_path) -> None:
    ignored_directory = tmp_path / "node_modules"
    ignored_directory.mkdir()
    ignored_file = ignored_directory / "package.js"
    ignored_file.write_text("password = 'this-should-not-count'", encoding="utf-8")
    env_example = tmp_path / ".env.example"
    env_example.write_text("SECRET_KEY=this-should-not-count", encoding="utf-8")

    result = RepositoryScanner().scan(tmp_path)

    assert result.files_scanned == 0
    assert result.total_findings == 0
    assert result.risk_level == "SECURE"


def test_json_report_generation(tmp_path) -> None:
    vulnerable_file = tmp_path / "app.env"
    vulnerable_file.write_text("DATABASE_URL=postgres://user:password@example.com:5432/app", encoding="utf-8")
    result = RepositoryScanner().scan(tmp_path)

    report_path = write_json_report(result, reports_directory=tmp_path / "reports")
    report_data = json.loads(report_path.read_text(encoding="utf-8"))

    assert report_path.exists()
    assert report_data["total_findings"] >= 1
    assert "findings" in report_data
