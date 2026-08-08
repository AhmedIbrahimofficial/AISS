"""Module 1 — Network Discovery Engine Tests"""
import asyncio
import pytest
from modules.network_discovery.utils import (
    parse_port_spec, service_name, get_mac_vendor,
    is_valid_ip, is_valid_cidr, expand_cidr, ttl_to_os_guess,
)
from modules.network_discovery.schemas import (
    HostDiscoveryRequest, PortScanRequest, FullScanRequest,
    PortInfo, HostInfo, DiscoveryResult,
)
from modules.network_discovery.discovery_service import NetworkDiscoveryService


# ── Utility tests ─────────────────────────────────────────────────────

def test_parse_port_spec_range():
    ports = parse_port_spec("80-85")
    assert ports == [80, 81, 82, 83, 84, 85]


def test_parse_port_spec_list():
    ports = parse_port_spec("80,443,8080")
    assert 80 in ports and 443 in ports and 8080 in ports


def test_parse_port_spec_common():
    ports = parse_port_spec("common")
    assert 80 in ports and 443 in ports
    assert len(ports) > 10


def test_service_name_known():
    assert service_name(80)   == "HTTP"
    assert service_name(443)  == "HTTPS"
    assert service_name(22)   == "SSH"
    assert service_name(3306) == "MySQL"


def test_service_name_unknown():
    result = service_name(54321)
    assert isinstance(result, str)


def test_mac_vendor_known():
    assert "VMware" in get_mac_vendor("00:50:56:aa:bb:cc")
    assert "Raspberry" in get_mac_vendor("b8:27:eb:11:22:33")


def test_mac_vendor_unknown():
    vendor = get_mac_vendor("ff:ff:ff:ff:ff:ff")
    assert isinstance(vendor, str)


def test_is_valid_ip():
    assert is_valid_ip("192.168.1.1") is True
    assert is_valid_ip("256.0.0.1") is False
    assert is_valid_ip("not-an-ip") is False


def test_is_valid_cidr():
    assert is_valid_cidr("192.168.1.0/24") is True
    assert is_valid_cidr("10.0.0.0/8") is True
    assert is_valid_cidr("999.0.0.0/24") is False


def test_expand_cidr():
    hosts = expand_cidr("192.168.1.0/30")
    assert "192.168.1.1" in hosts
    assert "192.168.1.2" in hosts
    assert len(hosts) == 2


def test_ttl_os_guess():
    assert "Linux" in ttl_to_os_guess(64)
    assert "Windows" in ttl_to_os_guess(128)
    assert "Cisco" in ttl_to_os_guess(255)
    assert "Unknown" in ttl_to_os_guess(0)


# ── Schema validation tests ───────────────────────────────────────────

def test_host_discovery_request_valid():
    req = HostDiscoveryRequest(target="192.168.1.1", method="ping", timeout=2.0)
    assert req.target == "192.168.1.1"


def test_host_discovery_request_empty_target():
    with pytest.raises(Exception):
        HostDiscoveryRequest(target="   ")


def test_port_scan_request_invalid_type():
    with pytest.raises(Exception):
        PortScanRequest(target="192.168.1.1", scan_type="invalid")


def test_port_scan_request_valid():
    req = PortScanRequest(target="10.0.0.1", ports="80,443", scan_type="connect")
    assert req.target == "10.0.0.1"


def test_discovery_result_schema():
    result = DiscoveryResult(
        target="192.168.1.1",
        scan_type="host_discovery",
        hosts_found=1,
        hosts_up=1,
        hosts_down=0,
        scan_duration_secs=0.5,
        hosts=[HostInfo(ip="192.168.1.1", status="up")],
    )
    assert result.hosts_found == 1
    assert result.hosts[0].ip == "192.168.1.1"


# ── Service tests (localhost only — no external network required) ──────

@pytest.mark.asyncio
async def test_host_discovery_localhost():
    """Discover localhost — should always be up."""
    svc    = NetworkDiscoveryService()
    result = await svc.discover_hosts("127.0.0.1", method="ping", timeout=3.0)
    assert result.target == "127.0.0.1"
    assert isinstance(result.hosts_found, int)
    assert result.scan_duration_secs >= 0


@pytest.mark.asyncio
async def test_port_scan_localhost_common():
    """Scan common ports on localhost — should complete without error."""
    svc    = NetworkDiscoveryService()
    result = await svc.scan_ports(
        target="127.0.0.1",
        ports="80,443,22,3306,8080",
        scan_type="connect",
        timeout=2.0,
        grab_banners=False,
    )
    assert result.target == "127.0.0.1"
    assert isinstance(result.open_ports, list)
    assert result.scan_duration_secs >= 0


@pytest.mark.asyncio
async def test_banner_grab_closed_port():
    """Banner grab on closed port should return empty string, not crash."""
    svc    = NetworkDiscoveryService()
    banner = await svc.port_engine._grab_banner("127.0.0.1", 19999, timeout=1.0)
    assert isinstance(banner, str)


if __name__ == "__main__":
    import subprocess, sys
    subprocess.run([sys.executable, "-m", "pytest", __file__, "-v"])
