from __future__ import annotations

from threatscribe.ioc import IOCType, extract, group, refang


def test_refang_undoes_common_defang():
    assert refang("hxxps://evil[.]com") == "https://evil.com"
    assert refang("8[.]8[.]8[.]8") == "8.8.8.8"
    assert refang("user[at]evil[dot]com") == "user@evil.com"


def test_extract_each_type():
    text = (
        "C2 at 185.220.101[.]47 and hxxps://evil-example[.]com/x reported. "
        "Hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855, "
        "contact bad@evil-example[.]com, exploits CVE-2024-3400, "
        "pay 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2."
    )
    by_type = group(extract(text))
    assert by_type["ipv4"] == ["185.220.101.47"]
    assert by_type["url"][0].startswith("https://evil-example.com")
    assert by_type["sha256"]
    assert by_type["email"] == ["bad@evil-example.com"]
    assert by_type["cve"] == ["CVE-2024-3400"]
    assert by_type["btc"]


def test_sha256_not_split_into_md5():
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    types = {i.type for i in extract(f"hash {h}")}
    assert IOCType.SHA256 in types
    assert IOCType.MD5 not in types  # the 64-hex is not reported as two MD5s


def test_domain_inside_url_not_double_counted():
    iocs = extract("visit https://cdn.evil-example.com/stage2.bin now")
    domains = [i.value for i in iocs if i.type is IOCType.DOMAIN]
    assert "cdn.evil-example.com" not in domains  # already inside the URL


def test_dedup():
    iocs = extract("CVE-2024-3400 and again CVE-2024-3400")
    assert sum(1 for i in iocs if i.type is IOCType.CVE) == 1
