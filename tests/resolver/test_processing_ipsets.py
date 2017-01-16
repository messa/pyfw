from pprint import pprint
from pytest import skip
import yaml
from textwrap import dedent

#from pyfw.resolver import determine_commands


sample_state_yaml = dedent('''
    state:
        ip6tables:
            filter:
                FORWARD:
                    default_action: ACCEPT
                    rules: []
                INPUT:
                    default_action: ACCEPT
                    rules: []
                OUTPUT:
                    default_action: ACCEPT
                    rules: []
        ipsets:
            fwd_allowed_dst_ports:
                header: range 0-20000
                members:
                - 1000
                - 2000
                type: bitmap:port
            fwd_allowed_src_hosts:
                header: family inet hashsize 1024 maxelem 65536
                members: []
                type: hash:ip
        iptables:
            filter:
                DOCKER:
                    default_action: '-'
                    rules: []
                DOCKER-ISOLATION:
                    default_action: '-'
                    rules:
                    - -j RETURN
                FORWARD:
                    default_action: ACCEPT
                    rules:
                    - -d 192.168.122.0/24 -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
                    - -s 192.168.122.0/24 -i virbr0 -j ACCEPT
                    - -i virbr0 -o virbr0 -j ACCEPT
                    - -o virbr0 -j REJECT --reject-with icmp-port-unreachable
                    - -i virbr0 -j REJECT --reject-with icmp-port-unreachable
                    - ! -i virbr0 -o virbr0 -m comment --comment fwd_filter -j PRE-LIBVIRT
                    - -j DOCKER-ISOLATION
                    - -o docker0 -j DOCKER
                    - -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
                    - -i docker0 ! -o docker0 -j ACCEPT
                    - -i docker0 -o docker0 -j ACCEPT
                INPUT:
                    default_action: ACCEPT
                    rules:
                    - -i virbr0 -p udp -m udp --dport 53 -j ACCEPT
                    - -i virbr0 -p tcp -m tcp --dport 53 -j ACCEPT
                    - -i virbr0 -p udp -m udp --dport 67 -j ACCEPT
                    - -i virbr0 -p tcp -m tcp --dport 67 -j ACCEPT
                    - -s 192.168.0.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_0 -j ACCEPT
                    - -s 192.168.0.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_0 -j ACCEPT
                    - -s 192.168.111.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_1 -j ACCEPT
                    - -s 192.168.222.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_2 -j ACCEPT
                OUTPUT:
                    default_action: ACCEPT
                    rules:
                    - -o virbr0 -p udp -m udp --dport 68 -j ACCEPT
                PRE-LIBVIRT:
                    default_action: '-'
                    rules: []
                PRE-LIVIRT:
                    default_action: '-'
                    rules: []
            mangle:
                FORWARD:
                    default_action: ACCEPT
                    rules: []
                INPUT:
                    default_action: ACCEPT
                    rules: []
                OUTPUT:
                    default_action: ACCEPT
                    rules: []
                POSTROUTING:
                    default_action: ACCEPT
                    rules:
                    - -o virbr0 -p udp -m udp --dport 68 -j CHECKSUM --checksum-fill
                PREROUTING:
                    default_action: ACCEPT
                    rules: []
            nat:
                DOCKER:
                    default_action: '-'
                    rules:
                    - -i docker0 -j RETURN
                INPUT:
                    default_action: ACCEPT
                    rules: []
                OUTPUT:
                    default_action: ACCEPT
                    rules:
                    - '! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER'
                POSTROUTING:
                    default_action: ACCEPT
                    rules:
                    - -s 192.168.122.0/24 -d 224.0.0.0/24 -j RETURN
                    - -s 192.168.122.0/24 -d 255.255.255.255/32 -j RETURN
                    - -s 192.168.122.0/24 ! -d 192.168.122.0/24 -p tcp -j MASQUERADE --to-ports 1024-65535
                    - -s 192.168.122.0/24 ! -d 192.168.122.0/24 -p udp -j MASQUERADE --to-ports 1024-65535
                    - -s 192.168.122.0/24 ! -d 192.168.122.0/24 -j MASQUERADE
                    - -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
                    - -s 192.168.99.0/24 ! -d 192.168.99.0/24 -j MASQUERADE
                PREROUTING:
                    default_action: ACCEPT
                    rules:
                    - -m addrtype --dst-type LOCAL -j DOCKER
''')


sample_state = yaml.load(sample_state_yaml)['state']


def test_sample_wish_create_new_ipset_bitmap_port():
    skip()
    wishes = yaml.load(dedent('''
        ipsets:
            new_ipset:
                type: bitmap:port
                header: range 0-20000
                members_equal:
                    - 1111
                    - 2222
    '''))
    cmds = determine_commands(sample_state, wishes)
    pprint(cmds, width=200)
    assert cmds == [
        'ipset -exist create new_ipset bitmap:port range 0-20000',
        'ipset -exist add new_ipset 2222',
        'ipset -exist add new_ipset 1111',
    ]


def test_sample_wish_create_new_ipset_hash_ip():
    skip()
    wishes = yaml.load(dedent('''
        ipsets:
            new_ipset:
                type: hash:ip
                members_equal:
                    - 10.20.30.40
    '''))
    cmds = determine_commands(sample_state, wishes)
    pprint(cmds, width=200)
    assert cmds == [
        'ipset -exist create new_ipset hash:ip',
        'ipset -exist add new_ipset 10.20.30.40',
    ]


def test_sample_wish_update_ipset_equal():
    skip()
    wishes = yaml.load(dedent('''
        ipsets:
            fwd_allowed_dst_ports:
                header: range 0-20000
                type: bitmap:port
                members_equal:
                    - 2000
                    - 3000
    '''))
    cmds = determine_commands(sample_state, wishes)
    pprint(cmds, width=200)
    assert cmds == [
        'ipset -exist del fwd_allowed_dst_ports 1000',
        'ipset -exist add fwd_allowed_dst_ports 3000',
    ]
