import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import ROOT, create_app


@pytest.fixture
def schema_dir(tmp_path):
    d = tmp_path / "schema"
    shutil.copytree(ROOT / "schema", d)
    return d


@pytest.fixture
def app(tmp_path, schema_dir):
    return create_app(str(tmp_path / "test.db"), schema_dir)


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def as_user(client):
    def call(user, method, path, **kw):
        return client.request(method, path, headers={"X-User-Id": user}, **kw)
    return call
