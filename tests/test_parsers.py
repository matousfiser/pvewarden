from pvewarden.guest import clean_tail, parse_services, parse_status, parse_upgradable


def by_name(text):
    return {p["name"]: p for p in parse_upgradable(text)}


def test_ubuntu_security_and_regular_updates():
    pkgs = by_name(
        "openssl\t3.0.13-1\t3.0.13-2\tUbuntu:noble-security,Ubuntu:noble-updates\t-\n"
        "vim\t9.1-1\t9.1-2\tUbuntu:noble-updates\t-\n"
    )
    assert pkgs["openssl"] == {
        "name": "openssl",
        "from": "3.0.13-1",
        "to": "3.0.13-2",
        "official": True,
        "security": True,
        "origin": ["Ubuntu:noble-security", "Ubuntu:noble-updates"],
        "held": False,
    }
    assert pkgs["vim"]["official"] and not pkgs["vim"]["security"]


def test_ubuntu_esm_is_official_security():
    p = by_name("libfoo\t1\t2\tUbuntuESMApps:jammy-apps-security\t-\n")["libfoo"]
    assert p["official"] and p["security"]


def test_debian_security():
    p = by_name("libc6\t2.36-9\t2.36-9+deb12u9\tDebian:bookworm-security\t-\n")["libc6"]
    assert p["official"] and p["security"]


def test_third_party_repo_named_like_the_distribution_is_not_official():
    # Docker's repository uses the suite name "noble" just like Ubuntu; only the origin tells them apart
    p = by_name("docker-ce\t5:29.9.1\t5:29.9.2\tDocker:noble\t-\n")["docker-ce"]
    assert not p["official"] and not p["security"]


def test_third_party_security_archive_is_not_official_security():
    p = by_name("tool\t1\t2\tVendor:stable-security\t-\n")["tool"]
    assert not p["official"] and not p["security"]


def test_held_and_garbage_lines():
    pkgs = by_name("forgejo\t7.0\t11.0\tForgejo:bullseye\theld\nnot a package line\n\n")
    assert list(pkgs) == ["forgejo"]
    assert pkgs["forgejo"]["held"]


def test_status_dedupes_reboot_packages():
    st = parse_status(
        "os=Ubuntu 24.04\nkernel=6.8.0-60\nreboot_required=yes\n"
        "reboot_pkg=linux-base\nreboot_pkg=libc6\nreboot_pkg=linux-base\nnoise without equals\n"
    )
    assert st["reboot_required"] is True
    assert st["reboot_pkgs"] == ["linux-base", "libc6"]
    assert st["kernel"] == "6.8.0-60"


def test_status_no_reboot():
    assert parse_status("reboot_required=no\n")["reboot_required"] is False


def test_services():
    assert parse_services("system=degraded\nfailed=nginx.service\nfailed=cron.service\n") == {
        "system": "degraded",
        "failed": ["nginx.service", "cron.service"],
    }
    assert parse_services("") == {"system": None, "failed": []}


def test_clean_tail_drops_dpkg_progress_noise():
    text = "Setting up git\n\n(Reading database ... \r(Reading database ... 5%\nRemoving old-kernel\nDone\n"
    assert clean_tail(text) == "Setting up git\nRemoving old-kernel\nDone"
    assert clean_tail("\n".join(str(i) for i in range(100)), lines=3) == "97\n98\n99"
