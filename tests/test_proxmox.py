import httpx
import pytest
import respx

from pvewarden.config import ProxmoxConfig
from pvewarden.errors import ProxmoxError
from pvewarden.proxmox import Guest, ProxmoxClient, split_tags

API = "https://pve.test:8006/api2/json"
CFG = ProxmoxConfig(host="pve.test", token_id="pvewarden@pve!t", token_secret="s3cret", verify_tls=False)
CT = Guest(101, "web", "lxc", "pve1", "running", ())
VM = Guest(102, "db", "qemu", "pve1", "running", ())


@pytest.fixture
def pve():
    return ProxmoxClient(CFG)


def test_split_tags():
    assert split_tags("a;b, c  d") == ("a", "b", "c", "d")
    assert split_tags("") == ()


@respx.mock
async def test_guests_sends_token_and_skips_templates(pve):
    route = respx.get(f"{API}/cluster/resources").respond(
        json={
            "data": [
                {"vmid": 101, "name": "web", "type": "lxc", "node": "pve1", "status": "running", "tags": "a;b"},
                {"vmid": 9000, "name": "tpl", "type": "qemu", "node": "pve1", "status": "stopped", "template": 1},
            ]
        }
    )
    guests = await pve.guests()
    assert guests == [Guest(101, "web", "lxc", "pve1", "running", ("a", "b"))]
    request = route.calls.last.request
    assert request.headers["Authorization"] == "PVEAPIToken=pvewarden@pve!t=s3cret"
    assert request.url.params["type"] == "vm"


@respx.mock
async def test_http_error_becomes_proxmox_error(pve):
    respx.get(f"{API}/cluster/resources").respond(403, text="Permission check failed")
    with pytest.raises(ProxmoxError, match="403"):
        await pve.guests()


@respx.mock
async def test_connection_error_becomes_proxmox_error(pve):
    respx.get(f"{API}/cluster/resources").mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(ProxmoxError, match="refused"):
        await pve.guests()


@respx.mock
async def test_guest_ips_qemu_agent_and_lxc(pve):
    respx.get(f"{API}/nodes/pve1/qemu/102/agent/network-get-interfaces").respond(
        json={
            "data": {
                "result": [
                    {"ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4"}]},
                    {
                        "ip-addresses": [
                            {"ip-address": "192.0.2.12", "ip-address-type": "ipv4"},
                            {"ip-address": "fe80::1", "ip-address-type": "ipv6"},
                        ]
                    },
                ]
            }
        }
    )
    respx.get(f"{API}/nodes/pve1/lxc/101/interfaces").respond(
        json={"data": [{"name": "lo", "inet": "127.0.0.1/8"}, {"name": "eth0", "inet": "192.0.2.11/24"}, {"name": "x"}]}
    )
    assert await pve.guest_ips(VM) == ["127.0.0.1", "192.0.2.12"]
    assert await pve.guest_ips(CT) == ["127.0.0.1", "192.0.2.11"]


@respx.mock
async def test_snapshot_waits_for_task(pve):
    upid = "UPID:pve1:0001:snap"
    create = respx.post(f"{API}/nodes/pve1/lxc/101/snapshot").respond(json={"data": upid})
    status = respx.get(f"{API}/nodes/pve1/tasks/{upid}/status").mock(
        side_effect=[
            httpx.Response(200, json={"data": {"status": "running"}}),
            httpx.Response(200, json={"data": {"status": "stopped", "exitstatus": "OK"}}),
        ]
    )
    pve_fast = ProxmoxClient(CFG)
    pve_fast.wait_task = lambda node, u, timeout=900: ProxmoxClient.wait_task(pve_fast, node, u, timeout, interval=0)
    await pve_fast.create_snapshot(CT, "pvewarden_x", "test")
    assert create.calls.last.request.content == b"snapname=pvewarden_x&description=test"
    assert status.call_count == 2


@respx.mock
async def test_failed_task_raises(pve):
    upid = "UPID:pve1:0002:reboot"
    respx.post(f"{API}/nodes/pve1/qemu/102/status/reboot").respond(json={"data": upid})
    respx.get(f"{API}/nodes/pve1/tasks/{upid}/status").respond(
        json={"data": {"status": "stopped", "exitstatus": "VM quit/powerdown failed"}}
    )
    with pytest.raises(ProxmoxError, match="powerdown failed"):
        await pve.reboot(VM)


@respx.mock
async def test_snapshots_hide_current(pve):
    respx.get(f"{API}/nodes/pve1/lxc/101/snapshot").respond(
        json={"data": [{"name": "current"}, {"name": "pvewarden_1", "snaptime": 1}]}
    )
    assert [s["name"] for s in await pve.snapshots(CT)] == ["pvewarden_1"]


@respx.mock
async def test_cluster_operations_go_to_the_guests_node(pve):
    respx.get(f"{API}/cluster/resources").respond(
        json={
            "data": [
                {"vmid": 101, "name": "a", "type": "lxc", "node": "pve1", "status": "running"},
                {"vmid": 202, "name": "b", "type": "qemu", "node": "pve2", "status": "running"},
            ]
        }
    )
    upid = "UPID:pve2:0003:snap"
    snap = respx.post(f"{API}/nodes/pve2/qemu/202/snapshot").respond(json={"data": upid})
    task = respx.get(f"{API}/nodes/pve2/tasks/{upid}/status").respond(
        json={"data": {"status": "stopped", "exitstatus": "OK"}}
    )
    guest = {g.vmid: g for g in await pve.guests()}[202]
    await pve.create_snapshot(guest, "pvewarden_x", "d")
    assert snap.called and task.called


@respx.mock
async def test_permissions_for_a_path(pve):
    route = respx.get(f"{API}/access/permissions").respond(
        json={"data": {"/vms/101": {"VM.Audit": 1, "VM.Snapshot": 1, "VM.Allocate": 0}}}
    )
    assert await pve.permissions("/vms/101") == {"/vms/101": {"VM.Audit", "VM.Snapshot"}}
    assert route.calls.last.request.url.params["path"] == "/vms/101"


def test_pinned_ca_tolerates_the_proxmox_root_ca(tmp_path):
    # Python 3.13 rejects CAs without a key usage extension (VERIFY_X509_STRICT); pve-root-ca.pem has none
    import ssl
    import subprocess

    ca = tmp_path / "ca.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
         "-subj", "/CN=Proxmox Virtual Environment", "-keyout", tmp_path / "ca.key", "-out", ca],
        check=True, capture_output=True,
    )  # fmt: skip
    client = ProxmoxClient(ProxmoxConfig(host="pve", token_id="t", token_secret="s", verify_tls=str(ca)))
    assert not client._verify.verify_flags & ssl.VERIFY_X509_STRICT
    assert client._verify.verify_mode == ssl.CERT_REQUIRED and client._verify.check_hostname
