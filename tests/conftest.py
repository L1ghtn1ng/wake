import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import wake


@pytest.fixture(autouse=True)
def isolated_computer_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep route tests independent from a developer's ignored runtime config."""
    config_path = Path(__file__).parent / 'fixtures' / 'computers.yaml'
    monkeypatch.setenv('WAKE_CONFIG', str(config_path))
    for cache_name in ('_config_cache', '_config_cache_path', '_config_cache_mtime_ns'):
        monkeypatch.setattr(wake, cache_name, None)
