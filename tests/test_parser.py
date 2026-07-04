import pytest
from sentinel_scan.utils.target_parser import TargetParser

@pytest.mark.asyncio
async def test_parse_ips():
    targets = ["127.0.0.1", "10.0.0.1"]
    parsed = await TargetParser.parse_targets(targets)
    assert "127.0.0.1" in parsed
    assert "10.0.0.1" in parsed
    assert len(parsed) == 2

@pytest.mark.asyncio
async def test_parse_cidr():
    targets = ["192.168.1.0/30"]
    parsed = await TargetParser.parse_targets(targets)
    # 192.168.1.0, .1, .2, .3
    assert "192.168.1.0" in parsed
    assert "192.168.1.3" in parsed
    assert len(parsed) == 4

@pytest.mark.asyncio
async def test_parse_hostname():
    targets = ["localhost"]
    parsed = await TargetParser.parse_targets(targets)
    assert "127.0.0.1" in parsed
