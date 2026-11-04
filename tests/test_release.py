"""New-version notice: what GitHub's answer means, how often it is asked, what the agent and doctor see."""

import json
import time

import httpx
import pytest
from conftest import make_config
from mcp import Client

from pvewarden import __version__
from pvewarden.config import ConfigError, parse
from pvewarden.doctor import check_version
from pvewarden.release import CHECK_EVERY_S, RETRY_AFTER_S, UPGRADE_HINT, compare, parse_releases, version_tuple
from pvewarden.tools import create_server

MAJOR, MINOR, PATCH = version_tuple(__version__)
NEXT = f"{MAJOR}.{MINOR}.{PATCH + 1}"
AFTER_NEXT = f"{MAJOR}.{MINOR}.{PATCH + 2}"


def gh(tag: str, body: str = "", **extra) -> dict:
    return {"tag_name": tag, "body": body, "html_url": f"https://example.test/{tag}", **extra}


def test_version_tuple():
    assert version_tuple("0.1.6") == (0, 1, 6)
    assert version_tuple("v0.10.2") == (0, 10, 2)
    assert version_tuple("0.2.0.dev0") == (0, 2, 0)
    assert version_tuple("latest") is None


def test_only_published_stable_releases_count_newest_first():
    releases = parse_releases(
        [
            gh("v0.1.6"),
            gh("v0.1.10"),
            gh("v0.2.0-rc1"),
            gh("v0.3.0", draft=True),
            gh("v0.4.0", prerelease=True),
            gh("nightly"),
            "not a release",
        ]
    )
    assert [r["version"] for r in releases] == ["0.1.10", "0.1.6"]  # 0.1.10 > 0.1.6: numbers, not text


def test_an_answer_that_is_not_a_list_is_an_error():
    with pytest.raises(ValueError):
        parse_releases({"message": "API rate limit exceeded"})


@pytest.mark.parametrize(
    ("body", "security"),
    [
        ("- **Security:** the token check accepted an empty token.", True),
        ("* **Security fix**: something", True),
        ("### Security\n\n- something", True),
        ("- Docs: docs/security.md explains the threat model.", False),
        ("- Fix: the security updates mode skipped held packages.", False),
        ("", False),
    ],
)
def test_security_releases_are_marked_in_their_notes(body, security):
    assert parse_releases([gh("v1.0.0", body)])[0]["security"] is security


def test_compare():
    releases = parse_releases([gh("v0.1.8"), gh("v0.1.7", "- **Security:** fix"), gh("v0.1.6")])
    assert compare(releases, "0.1.8") == {"version": "0.1.8"}
    assert compare(releases, "0.1.9") == {"version": "0.1.9"}  # a build newer than any release
    newer = compare(releases, "0.1.6")
    assert newer == {
        "version": "0.1.6",
        "new_version": "0.1.8",
        "security_fix": True,  # 0.1.7 fixed a security problem, 0.1.6 does not have the fix
        "release_notes": "https://example.test/v0.1.8",
        "upgrade": UPGRADE_HINT,
    }
    assert compare(releases, "0.1.7")["security_fix"] is False  # already has that fix
    assert compare([], "0.1.6") == {"version": "0.1.6"}


def test_config_option(tmp_path):
    assert parse(make_config(tmp_path)).check_new_version is True
    assert parse(make_config(tmp_path, check_new_version=False)).check_new_version is False
    with pytest.raises(ConfigError, match="check_new_version"):
        parse(make_config(tmp_path, check_new_version="no"))


# --- how often GitHub is asked ---------------------------------------------------------------


async def test_asks_once_a_day_and_keeps_the_answer(app, github):
    github.release(NEXT)
    assert (await app.release.notice())["new_version"] == NEXT
    assert (await app.release.notice())["new_version"] == NEXT
    assert github.calls == 1
    cache = json.loads(app.release.path.read_text())
    cache["checked"] = cache["attempted"] = time.time() - CHECK_EVERY_S - 1
    app.release.path.write_text(json.dumps(cache))
    github.release(AFTER_NEXT)
    assert (await app.release.notice())["new_version"] == AFTER_NEXT
    assert github.calls == 2


async def test_a_failed_check_keeps_the_last_answer_and_waits_an_hour(app, github):
    github.release(NEXT)
    await app.release.notice()
    cache = json.loads(app.release.path.read_text())
    cache["checked"] = cache["attempted"] = time.time() - CHECK_EVERY_S - 1
    app.release.path.write_text(json.dumps(cache))
    github.error = httpx.ConnectError("no route to host")
    assert (await app.release.notice())["new_version"] == NEXT  # still known
    assert (await app.release.notice())["new_version"] == NEXT
    assert github.calls == 2  # the failure is not retried on every call
    cache = json.loads(app.release.path.read_text())
    assert "ConnectError" in cache["error"]
    cache["attempted"] = time.time() - RETRY_AFTER_S - 1
    app.release.path.write_text(json.dumps(cache))
    github.error = None
    await app.release.notice()
    assert github.calls == 3
    assert "error" not in json.loads(app.release.path.read_text())


async def test_no_network_no_cache_is_not_a_problem(app, github):
    github.error = httpx.ConnectError("no route to host")
    assert await app.release.notice() == {"version": __version__}


async def test_a_broken_cache_file_is_asked_again(app, github):
    app.release.path.parent.mkdir(parents=True, exist_ok=True)
    app.release.path.write_text("{not json")
    github.release(NEXT)
    assert (await app.release.notice())["new_version"] == NEXT


async def test_turned_off_never_asks(app, github):
    app.release.enabled = False
    github.release(NEXT)
    assert await app.release.notice() == {"version": __version__}
    assert github.calls == 0 and not app.release.path.exists()


# --- what the agent and doctor see ---------------------------------------------------------


def result(res) -> dict:
    return res.structured_content or json.loads(" ".join(getattr(c, "text", "") for c in res.content))


async def test_check_updates_tells_the_agent(app, github):
    github.release(NEXT, "- **Security:** fix")
    async with Client(create_server(app)) as client:
        res = await client.call_tool("check_updates", {"vmids": [101]})
    assert not res.is_error
    data = result(res)
    assert [g["vmid"] for g in data["guests"]] == [101]
    assert data["pvewarden"]["new_version"] == NEXT and data["pvewarden"]["security_fix"] is True
    assert data["pvewarden"]["upgrade"] == UPGRADE_HINT


async def test_check_updates_without_a_new_version(app):
    async with Client(create_server(app)) as client:
        res = await client.call_tool("check_updates", {"vmids": [101]})
    assert result(res)["pvewarden"] == {"version": __version__}


async def test_check_updates_errors_still_reach_the_agent(app, github):
    async with Client(create_server(app)) as client:
        res = await client.call_tool("check_updates", {"vmids": [999]})
    assert res.is_error and "999" in " ".join(getattr(c, "text", "") for c in res.content)


async def test_doctor_newest(app):
    r = await check_version(app)
    assert r.status == "ok" and r.detail == f"{__version__}, the newest release"


async def test_doctor_asks_now_even_with_a_fresh_answer(app, github):
    await app.release.notice()
    github.release(NEXT, "### Security\n- fix")
    r = await check_version(app)
    assert r.status == "warn"
    assert r.detail == f"pvewarden {NEXT} is out, WITH SECURITY FIXES (this is {__version__})"
    assert r.hint == UPGRADE_HINT


async def test_doctor_without_network(app, github):
    github.error = httpx.ConnectError("no route to host")
    r = await check_version(app)
    assert r.status == "info" and "could not ask GitHub" in r.detail and "api.github.com" in r.hint


async def test_doctor_turned_off(app, github):
    app.release.enabled = False
    r = await check_version(app)
    assert r.status == "info" and "check_new_version = false" in r.detail
    assert github.calls == 0
