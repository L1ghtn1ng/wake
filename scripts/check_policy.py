"""Check Wake's reviewed Flasgo policy using an isolated CI configuration."""

import argparse
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / 'baseline.json'

# These routes enforce proxy identity and device access inside Wake's handlers.
# Do not mark them public or broadly ignore FG011 to silence deployment checks.
APPLICATION_AUTH_ROUTES = ('/terminal', '/ws/terminal')
EXPECTED_ISSUES = [
    {
        'code': 'FG011',
        'message': f'Route {path} has no declared access policy; use public=True or authorize().',
        'severity': 'warning',
    }
    for path in APPLICATION_AUTH_ROUTES
]


def policy_environment() -> dict[str, str]:
    """Avoid inheriting deployment credentials or developer-specific Wake settings."""
    environment = {key: value for key, value in os.environ.items() if not key.startswith(('WAKE_', 'FLASGO_'))}
    environment.update(
        FLASGO_SECRET_KEY=secrets.token_hex(32),
        FLASGO_METRICS_TOKEN=secrets.token_hex(32),
        WAKE_TERMINAL_ENABLED='1',
        WAKE_TERMINAL_USERS='policy-review',
        WAKE_CONFIG=str(ROOT / 'tests' / 'fixtures' / 'computers.yaml'),
    )
    return environment


def acceptable_report(report: object, returncode: int) -> bool:
    """Accept exactly the two reviewed custom-auth warnings and no policy drift."""
    return (
        returncode == 1
        and isinstance(report, dict)
        and report.get('passed') is False
        and report.get('changes') == []
        and sorted(report.get('issues', []), key=lambda issue: issue['message']) == EXPECTED_ISSUES
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, default=BASELINE)
    parser.add_argument('--update', action='store_true', help='Explicitly replace the baseline for review')
    args = parser.parse_args()
    environment = policy_environment()
    cli = [sys.executable, '-c', 'from flasgo.cli import main; raise SystemExit(main())']
    check = [*cli, 'check', 'wake:base_app', '--deploy', '--json']
    if not args.update:
        check.extend(['--against', str(args.baseline.resolve())])
    result = subprocess.run(check, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30, check=False)  # noqa: S603
    if result.stderr:
        print(result.stderr, file=sys.stderr, end='')
    try:
        accepted = acceptable_report(json.loads(result.stdout), result.returncode)
    except ValueError, KeyError, TypeError:
        accepted = False
    if not accepted:
        print(result.stdout, end='')
        print('Route-policy check failed; review the reported issues and baseline changes.', file=sys.stderr)
        return 1
    if args.update:
        result = subprocess.run(  # noqa: S603
            [*cli, 'routes', 'wake:base_app', '--json', '--output', str(args.baseline.resolve())],
            cwd=ROOT,
            env=environment,
            timeout=30,
            check=False,
        )
        if result.returncode:
            return result.returncode
        print(f'Updated {args.baseline}; review the diff before committing.')
    else:
        print('Route-policy baseline and deployment controls passed.')
    print('Terminal authorization is application-owned; tests/test_ssh_terminal.py verifies those controls.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
