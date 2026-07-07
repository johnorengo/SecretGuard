from secretguard.detector import SecretDetector, mask_secret


def test_detects_aws_access_key() -> None:
    detector = SecretDetector()
    content = "AWS_ACCESS_KEY_ID='AKIA1234567890ABCDEF'"

    findings = detector.detect(content, "settings.py")

    assert len(findings) == 1
    assert findings[0].rule_name == "AWS Access Key"
    assert findings[0].severity == "HIGH"
    assert findings[0].line_number == 1


def test_detects_password_variable() -> None:
    detector = SecretDetector()
    content = 'password = "super-secret-password"'

    findings = detector.detect(content, "config.py")

    assert any(finding.rule_name == "Password Variable" for finding in findings)


def test_masks_secret_values() -> None:
    assert mask_secret("AKIA1234567890ABCDEF") == "AKIA...CDEF"
    assert mask_secret("short") == "*****"


def test_ignores_common_framework_and_variable_false_positives() -> None:
    detector = SecretDetector()
    content = "\n".join(
        [
            "$passwordRoute = auth('subcounty')->check()",
            "$schoolTokens = $tokens($schoolName);",
            "$configuredToken = config('services.external_user_sync.token');",
            "token = csrf_token_from(response.text)",
            "$user->password = Hash::make($validated['password']);",
        ]
    )

    findings = detector.detect(content, "framework.php")

    assert findings == []


def test_detects_real_environment_secret_assignments() -> None:
    detector = SecretDetector()
    github_token = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456"
    content = "\n".join(
        [
            "API_KEY=dummy_api_key_value_abcdefghijklmnopqrstuvwxyz",
            "DB_PASSWORD=myVeryLongDatabasePassword123",
            f"GITHUB_TOKEN={github_token}",
        ]
    )

    findings = detector.detect(content, ".env")
    rule_names = [finding.rule_name for finding in findings]

    assert rule_names == [
        "Environment Secret",
        "Environment Secret",
        "Environment Secret",
    ]
