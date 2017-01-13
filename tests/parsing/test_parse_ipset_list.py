from pprint import pprint
from textwrap import dedent

from pyfw.parsing import parse_ipset_list


sample_ipset_list = dedent('''
    Name: fwd_allowed_src_hosts
    Type: hash:ip
    Revision: 3
    Header: family inet hashsize 1024 maxelem 65536
    Size in memory: 16536
    References: 2
    Members:
    37.157.193.242

    Name: fwd_allowed_dst_ports
    Type: bitmap:port
    Revision: 2
    Header: range 0-20000
    Size in memory: 2616
    References: 2
    Members:
    1234
    8099
''')


def test_parse_ipset_list():
    ipsets = parse_ipset_list(sample_ipset_list)
    pprint(ipsets)
    assert ipsets == {
        'fwd_allowed_dst_ports': {
            'type': 'bitmap:port',
            'header': 'range 0-20000',
            'members': ['1234', '8099'],
        },
        'fwd_allowed_src_hosts': {
            'type': 'hash:ip',
            'header': 'family inet hashsize 1024 maxelem 65536',
            'members': ['37.157.193.242'],
        },
    }
