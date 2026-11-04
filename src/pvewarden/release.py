"""Is there a newer pvewarden? Only tells; it never upgrades anything.

The server asks GitHub's list of releases at most once a day and keeps the answer in
state_dir/release-check.json. The request is a plain GET with no data about this installation
(User-Agent "pvewarden", no version, no guest names). Turned off with `check_new_version = false`.

Upgrading stays a human's job on the Proxmox host (`pvewarden-setup upgrade`): the server has no
root on the host and gets none for this.
"""

import json
import logging
import os
import re
import time
from pathlib import Path

import httpx

from pvewarden import __version__

REPO = "matousfiser/pvewarden"
RELEASES_URL = f"https://api.github.com/repos/{REPO}/releases?per_page=30"
CHECK_EVERY_S = 24 * 3600
# after a failed check, try again sooner than a day, but not on every call
RETRY_AFTER_S = 3600
UPGRADE_HINT = "on the Proxmox host, as root: pvewarden-setup upgrade"
# a release whose notes have a bullet starting with **Security or a heading "## Security" fixes a
# security problem (see CHANGELOG.md)
SECURITY_MARK = re.compile(r"(?im)^\s*(?:[-*]\s+\*\*security\b|#{2,}\s*security\b)")
TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")

log = logging.getLogger(__name__)


def version_tuple(version: str) -> tuple[int, int, int] | None:
    """(0, 1, 6) for '0.1.6', 'v0.1.6' or '0.1.6.dev0'; None if it is not a version."""
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", version)
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def parse_releases(data: object) -> list[dict]:
    """Published, stable releases from GitHub's answer: version, url, security. Newest first."""
    if not isinstance(data, list):
        raise ValueError("GitHub's answer is not a list of releases")
    out = []
    for r in data:
        if not isinstance(r, dict) or r.get("draft") or r.get("prerelease"):
            continue
        m = TAG.match(str(r.get("tag_name", "")))
        if not m:
            continue
        out.append(
            {
                "version": f"{m[1]}.{m[2]}.{m[3]}",
                "url": str(r.get("html_url", "")),
                "security": bool(SECURITY_MARK.search(str(r.get("body") or ""))),
            }
        )
    out.sort(key=lambda r: version_tuple(r["version"]), reverse=True)
    return out


def compare(releases: list[dict], current: str = __version__) -> dict:
    """What the agent and doctor show: this version and, if there is one, the newer release."""
    mine = version_tuple(current)
    newer = [r for r in releases if mine is not None and version_tuple(r["version"]) > mine]
    out: dict = {"version": current}
    if newer:
        out.update(
            new_version=newer[0]["version"],
            # a security fix in any release since this one counts, not only in the newest
            security_fix=any(r["security"] for r in newer),
            release_notes=newer[0]["url"],
            upgrade=UPGRADE_HINT,
        )
    return out


async def fetch_releases(timeout: float = 10) -> list[dict]:
    headers = {"User-Agent": "pvewarden", "Accept": "application/vnd.github+json"}
    async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
        r = await client.get(RELEASES_URL)
        r.raise_for_status()
        return parse_releases(r.json())


class ReleaseCheck:
    def __init__(self, state_dir: Path, enabled: bool = True):
        self.enabled = enabled
        self.path = state_dir / "release-check.json"

    def cached(self) -> dict | None:
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def _save(self, data: dict) -> None:
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(data))
            os.replace(tmp, self.path)
        except OSError as e:
            log.warning("cannot write %s: %s", self.path, e)

    async def refresh(self) -> dict:
        """Ask GitHub now. Keeps the last good list when the check fails; raises nothing."""
        cache = self.cached() or {}
        now = time.time()
        try:
            releases = await fetch_releases()
        except (httpx.HTTPError, ValueError) as e:
            cache.update(attempted=now, error=f"{type(e).__name__}: {e}"[:300])
            self._save(cache)
            return cache
        cache = {"checked": now, "attempted": now, "releases": releases}
        self._save(cache)
        result = compare(releases)
        if "new_version" in result:
            log.warning(
                "pvewarden %s is out (this is %s)%s; %s",
                result["new_version"],
                __version__,
                ", with security fixes" if result["security_fix"] else "",
                UPGRADE_HINT,
            )
        return cache

    async def notice(self) -> dict:
        """For the agent: this version and a newer one if known. Asks GitHub when the answer is a
        day old (an hour after a failure); a failed check is not the agent's problem."""
        if not self.enabled:
            return {"version": __version__}
        cache = self.cached() or {}
        now = time.time()
        stale = now - cache.get("checked", 0) > CHECK_EVERY_S and now - cache.get("attempted", 0) > RETRY_AFTER_S
        if stale:
            cache = await self.refresh()
        return compare(cache.get("releases", []))
