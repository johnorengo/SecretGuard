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
