import json
import subprocess
import sys

import pytest

from scripts.check_policy import BASELINE, EXPECTED_ISSUES, ROOT, acceptable_report


def test_policy_check_uses_isolated_settings_and_does_not_rewrite_baseline(monkeypatch) -> None:
    monkeypatch.setenv('WAKE_TERMINAL_LOCAL_DEVELOPMENT', 'invalid')
    monkeypatch.setenv('WAKE_ALLOWED_HOSTS', 'developer.example')
    monkeypatch.setenv('FLASGO_SECRET_KEY', 'invalid')
    original = BASELINE.read_bytes()
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(ROOT / 'scripts/check_policy.py')],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert BASELINE.read_bytes() == original


@pytest.mark.parametrize('change', ['csrf', 'route', 'missing'])
def test_policy_check_rejects_drift_or_missing_baseline(tmp_path, change) -> None:
    baseline = tmp_path / 'policy.json'
    policy = json.loads(BASELINE.read_text())
    if change == 'csrf':
        policy['controls']['csrf_enabled'] = False
    elif change == 'route':
        policy['routes'].pop()
    if change != 'missing':
        baseline.write_text(json.dumps(policy))
    original = baseline.read_bytes() if baseline.exists() else None
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(ROOT / 'scripts/check_policy.py'), '--baseline', str(baseline)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 1
    assert 'Route-policy check failed' in result.stderr
    assert (baseline.read_bytes() if baseline.exists() else None) == original


def test_only_exact_custom_authorization_warnings_are_accepted() -> None:
    report = {'passed': False, 'changes': [], 'issues': EXPECTED_ISSUES}
    assert acceptable_report(report, 1)
    assert not acceptable_report(report, 0)
    assert not acceptable_report(report, 2)
    assert not acceptable_report({**report, 'issues': []}, 1)
    assert not acceptable_report({**report, 'changes': [{'section': 'controls'}]}, 1)
    for issue in (
        {'code': 'FG005', 'message': 'CSRF controls relaxed', 'severity': 'warning'},
        {
            'code': 'FG011',
            'message': 'Route /new has no declared access policy; use public=True or authorize().',
            'severity': 'warning',
        },
    ):
        assert not acceptable_report({**report, 'issues': [*EXPECTED_ISSUES, issue]}, 1)
