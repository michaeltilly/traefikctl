from pathlib import Path

import pytest

from traefikctl.config import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    s = Settings()
    s.dynamic_dir = tmp_path
    return s
