"""deploy/install-server.sh for real, as pvewarden-setup runs it: a fresh install, then an upgrade.

Run with: pytest -m integration   (needs Docker and network access for apt and PyPI)
"""

import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration
ROOT = Path(__file__).parent.parent.parent


def sh(*args, check=True, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, check=check, **kwargs)


@pytest.fixture(scope="module", params=["debian:12", "debian:13"])
def server(request, tmp_path_factory):
    if not shutil.which("docker") or sh("docker", "info", check=False).returncode != 0:
        pytest.skip("docker not available")
    name = f"pvewarden-test-server-{uuid.uuid4().hex[:8]}"
    sh("docker", "run", "-d", "--name", name, request.param, "sleep", "infinity")
    try:
        # no systemd in the container: systemctl only has to succeed
        sh("docker", "exec", name, "sh", "-c", "printf '#!/bin/sh\\nexit 0\\n' > /usr/local/bin/systemctl && "
           "chmod +x /usr/local/bin/systemctl")  # fmt: skip
        src = tmp_path_factory.mktemp("src")
        for d in ("deploy", "src"):
            shutil.copytree(ROOT / d, src / d, ignore=shutil.ignore_patterns("__pycache__"))
        for f in ("requirements.lock", "config.example.toml"):
            shutil.copy(ROOT / f, src / f)
        sh("docker", "cp", str(src), f"{name}:/root/pvewarden-src")
        yield name
    finally:
        sh("docker", "rm", "-f", name, check=False)


def install(name):
    return sh("docker", "exec", name, "bash", "/root/pvewarden-src/deploy/install-server.sh", "192.0.2.50",
              check=False, timeout=900)  # fmt: skip


def test_fresh_install_then_upgrade_both_succeed(server):
    first = install(server)
    assert first.returncode == 0, first.stdout + first.stderr
    assert "Installed pvewarden" in first.stdout and "Next: edit" in first.stdout

    # pvewarden-setup upgrade runs it again on an existing installation; it must exit 0 there too,
    # or the setup stops before restarting the service and enrolling the guests
    again = install(server)
    assert again.returncode == 0, again.stdout + again.stderr
    assert "Installed pvewarden" in again.stdout and "Next: edit" not in again.stdout

    version = sh("docker", "exec", server, "runuser", "-u", "pvewarden", "--", "pvewarden", "--version")
    assert version.stdout.startswith("pvewarden ")
    perms = sh("docker", "exec", server, "stat", "-c", "%a %U", "/var/lib/pvewarden/keys").stdout.split()
    assert perms == ["700", "pvewarden"]
