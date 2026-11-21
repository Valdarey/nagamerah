from nagamerah.ioc.parser import parse
import pytest
def test_parse_ipv4(): assert parse('8.8.8.8')['type']=='IPv4'
def test_defang_domain(): assert parse('evil[.]example')['value']=='evil.example'
def test_hash(): assert parse('44d88612fea8a8f36de82e1278abb02f')['type']=='MD5'
def test_invalid():
    with pytest.raises(ValueError): parse('')
