from pprint import pprint
from pytest import skip
import yaml
from textwrap import dedent

from pyfw.resolver import determine_desired_state, determine_commands
from pyfw.util import print_diff


sample_state_yaml = dedent('''
pyfw_state:
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
            members: []
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


sample_state = yaml.load(sample_state_yaml)['pyfw_state']


def _load_wishes(s):
    return yaml.load(dedent(s))['pyfw_wishes']


def test_multiple_sample_wishes():
    wishes = _load_wishes('''
    pyfw_wishes:
        iptables:
            filter:
                INPUT:
                    rules:
                    # this rule is the same as already present, but multiple times
                    - sample_rule_0: -s 192.168.0.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_0 -j ACCEPT
                    # this rule is the same as already present - no changes
                    - sample_rule_1: -s 192.168.111.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_1 -j ACCEPT
                    # this rule has same comment as already present but is different - should update
                    - sample_rule_2: -s 192.168.222.222/32 -p tcp -m tcp --dport 2222 -m comment --comment sample_rule_2 -j ACCEPT
                    # this rule is new - should be added
                    - sample_rule_3: -s 192.168.222.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_3 -j ACCEPT
                FORWARD:
                    rules:
                    - fwd_filter: '! -i virbr0 -o virbr0 -m comment --comment fwd_filter -j PRE-LIBVIRT'
                    - fwd_filter_new: -m comment --comment fwd_filter_new -j TEST
    ''')

    print('wishes:')
    pprint(wishes, width=200)

    desired_state = determine_desired_state(sample_state, wishes)

    print_diff(sample_state, desired_state, 'sample_state', 'desired_state')

    cmds = determine_commands(sample_state, desired_state)

    print()
    print('cmds:')
    pprint(cmds, width=200)

    assert cmds == [
        'iptables -w -t filter -I FORWARD 1 ! -i virbr0 -o virbr0 -m comment --comment fwd_filter -j PRE-LIBVIRT',
        'iptables -w -t filter -I FORWARD 2 -m comment --comment fwd_filter_new -j TEST',
        '',
        'iptables -w -t filter -I FORWARD 8 -m comment --comment _pyfw_temp_ -j DOCKER-ISOLATION',
        'iptables -w -t filter -D FORWARD -j DOCKER-ISOLATION',
        'iptables -w -t filter -I FORWARD 8 -j DOCKER-ISOLATION',
        'iptables -w -t filter -D FORWARD -m comment --comment _pyfw_temp_ -j DOCKER-ISOLATION',
        '',
        'iptables -w -t filter -I FORWARD 9 -m comment --comment _pyfw_temp_ -o docker0 -j DOCKER',
        'iptables -w -t filter -D FORWARD -o docker0 -j DOCKER',
        'iptables -w -t filter -I FORWARD 9 -o docker0 -j DOCKER',
        'iptables -w -t filter -D FORWARD -m comment --comment _pyfw_temp_ -o docker0 -j DOCKER',
        '',
        'iptables -w -t filter -I FORWARD 10 -m comment --comment _pyfw_temp_ -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
        'iptables -w -t filter -D FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
        'iptables -w -t filter -I FORWARD 10 -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
        'iptables -w -t filter -D FORWARD -m comment --comment _pyfw_temp_ -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
        '',
        'iptables -w -t filter -I FORWARD 11 -m comment --comment _pyfw_temp_ -i docker0 ! -o docker0 -j ACCEPT',
        'iptables -w -t filter -D FORWARD -i docker0 ! -o docker0 -j ACCEPT',
        'iptables -w -t filter -I FORWARD 11 -i docker0 ! -o docker0 -j ACCEPT',
        'iptables -w -t filter -D FORWARD -m comment --comment _pyfw_temp_ -i docker0 ! -o docker0 -j ACCEPT',
        '',
        'iptables -w -t filter -I FORWARD 12 -m comment --comment _pyfw_temp_ -i docker0 -o docker0 -j ACCEPT',
        'iptables -w -t filter -D FORWARD -i docker0 -o docker0 -j ACCEPT',
        'iptables -w -t filter -I FORWARD 12 -i docker0 -o docker0 -j ACCEPT',
        'iptables -w -t filter -D FORWARD -m comment --comment _pyfw_temp_ -i docker0 -o docker0 -j ACCEPT',
        '',
        'iptables -w -t filter -D FORWARD -i virbr0 -o virbr0 -m comment --comment fwd_filter -j PRE-LIBVIRT',
        'iptables -w -t filter -I INPUT 1 -s 192.168.0.0/24 -p tcp -m tcp --dport 9999 -m comment --comment _pyfw_temp_sample_rule_0 -j ACCEPT',
        'iptables -w -t filter -D INPUT -s 192.168.0.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_0 -j ACCEPT',
        'iptables -w -t filter -D INPUT -s 192.168.0.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_0 -j ACCEPT',
        'iptables -w -t filter -I INPUT 1 -s 192.168.0.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_0 -j ACCEPT',
        'iptables -w -t filter -D INPUT -s 192.168.0.0/24 -p tcp -m tcp --dport 9999 -m comment --comment _pyfw_temp_sample_rule_0 -j ACCEPT',
        '',
        'iptables -w -t filter -I INPUT 2 -s 192.168.111.0/24 -p tcp -m tcp --dport 9999 -m comment --comment _pyfw_temp_sample_rule_1 -j ACCEPT',
        'iptables -w -t filter -D INPUT -s 192.168.111.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_1 -j ACCEPT',
        'iptables -w -t filter -I INPUT 2 -s 192.168.111.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_1 -j ACCEPT',
        'iptables -w -t filter -D INPUT -s 192.168.111.0/24 -p tcp -m tcp --dport 9999 -m comment --comment _pyfw_temp_sample_rule_1 -j ACCEPT',
        '',
        'iptables -w -t filter -I INPUT 3 -s 192.168.222.222/32 -p tcp -m tcp --dport 2222 -m comment --comment sample_rule_2 -j ACCEPT',
        'iptables -w -t filter -I INPUT 4 -s 192.168.222.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_3 -j ACCEPT',
        'iptables -w -t filter -D INPUT -s 192.168.222.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_2 -j ACCEPT',
    ]


def test_sample_wish_replace_duplicate_rules():
    wishes = _load_wishes('''
    pyfw_wishes:
        iptables:
            filter:
                INPUT:
                    rules:
                    # this rule is the same as already present, but multiple times
                    - sample_rule_0: -s 192.168.0.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_0 -j ACCEPT
    ''')
    desired_state = determine_desired_state(sample_state, wishes)
    cmds = determine_commands(sample_state, desired_state)
    print_diff(sample_state, desired_state, 'sample_state', 'desired_state')
    pprint(cmds, width=200)
    assert cmds == [
        'iptables -w -t filter -I INPUT 1 -s 192.168.0.0/24 -p tcp -m tcp --dport 9999 -m comment --comment _pyfw_temp_sample_rule_0 -j ACCEPT',
        'iptables -w -t filter -D INPUT -s 192.168.0.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_0 -j ACCEPT',
        'iptables -w -t filter -D INPUT -s 192.168.0.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_0 -j ACCEPT',
        'iptables -w -t filter -I INPUT 1 -s 192.168.0.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_0 -j ACCEPT',
        'iptables -w -t filter -D INPUT -s 192.168.0.0/24 -p tcp -m tcp --dport 9999 -m comment --comment _pyfw_temp_sample_rule_0 -j ACCEPT',
    ]


def test_sample_wish_already_present_rule_no_changes():
    skip() # TODO: this should not test reorder
    wishes = _load_wishes('''
    pyfw_wishes:
        iptables:
            filter:
                INPUT:
                    rules:
                    # this rule is the same as already present - no changes
                    - sample_rule_1: -s 192.168.111.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_1 -j ACCEPT
    ''')
    desired_state = determine_desired_state(sample_state, wishes)
    cmds = determine_commands(sample_state, desired_state)
    print_diff(sample_state, desired_state, 'sample_state', 'desired_state')
    pprint(cmds, width=200)
    assert cmds == [
        'iptables -w -t filter -I INPUT 1 -s 192.168.111.0/24 -p tcp -m tcp --dport 9999 -m comment --comment _pyfw_temp_sample_rule_1 -j ACCEPT',
        'iptables -w -t filter -D INPUT -s 192.168.111.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_1 -j ACCEPT',
        'iptables -w -t filter -I INPUT 1 -s 192.168.111.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_1 -j ACCEPT',
        'iptables -w -t filter -D INPUT -s 192.168.111.0/24 -p tcp -m tcp --dport 9999 -m comment --comment _pyfw_temp_sample_rule_1 -j ACCEPT',
    ]


def test_sample_wish_update_rule():
    skip() # TODO: this should not test reorder
    wishes = _load_wishes('''
    pyfw_wishes:
        iptables:
            filter:
                INPUT:
                    # this rule has same comment as already present but is different - should update
                    - sample_rule_2: -s 192.168.222.222/32 -p tcp -m tcp --dport 2222 -m comment --comment sample_rule_2 -j ACCEPT
    ''')
    desired_state = determine_desired_state(sample_state, wishes)
    cmds = determine_commands(sample_state, desired_state)
    print_diff(sample_state, desired_state, 'sample_state', 'desired_state')
    pprint(cmds, width=200)
    assert cmds == [
        'iptables -w -t filter -A INPUT -s 192.168.222.222/32 -p tcp -m tcp --dport 2222 -m comment --comment _pyfwtmp__sample_rule_2 -j ACCEPT',
        'iptables -w -t filter -D INPUT -s 192.168.222.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_2 -j ACCEPT',
        'iptables -w -t filter -A INPUT -s 192.168.222.222/32 -p tcp -m tcp --dport 2222 -m comment --comment sample_rule_2 -j ACCEPT',
        'iptables -w -t filter -D INPUT -s 192.168.222.222/32 -p tcp -m tcp --dport 2222 -m comment --comment _pyfwtmp__sample_rule_2 -j ACCEPT',
    ]


def test_sample_wish_append_new_rule():
    # TODO fix test and remove skip
    skip()
    wishes = yaml.load(dedent('''
        iptables:
            filter:
                INPUT:
                    - sample_rule_3:
                        # this rule is new - should be added
                        rule: -s 192.168.222.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_3 -j ACCEPT
    '''))
    cmds = determine_commands(sample_state, wishes)
    pprint(cmds, width=200)
    assert cmds == [
        'iptables -w -t filter -A INPUT -s 192.168.222.0/24 -p tcp -m tcp --dport 9999 -m comment --comment sample_rule_3 -j ACCEPT',
    ]


def test_sample_wish_insert_new_rule():
    # TODO fix test and remove skip
    skip()
    wishes = yaml.load(dedent('''
        iptables:
            filter:
                FORWARD:
                    - fwd_filter_new:
                        before: -o virbr0 -j REJECT
                        rule: -m comment --comment fwd_filter_new -j TEST

    '''))

    print('wishes:')
    pprint(wishes, width=200)

    cmds = determine_commands(sample_state, wishes)

    print()
    print('cmds:')
    pprint(cmds, width=200)

    assert cmds == [
        'iptables -w -t filter -I FORWARD -m comment --comment fwd_filter_new -j TEST',
    ]


def test_sample_wish_reorder_rule():
    # TODO fix test and remove skip
    skip()
    wishes = yaml.load(dedent('''
        iptables:
            filter:
                FORWARD:
                    - fwd_filter:
                        before: -o virbr0 -j REJECT
                        rule: ! -i virbr0 -o virbr0 -m comment --comment fwd_filter -j PRE-LIBVIRT
    '''))
    cmds = determine_commands(sample_state, wishes)
    pprint(cmds, width=200)
    assert cmds == [
        'iptables -w -t filter -I FORWARD -i virbr0 -o virbr0 -m comment --comment _pyfwtmp__fwd_filter -j PRE-LIBVIRT',
        'iptables -w -t filter -D FORWARD -i virbr0 -o virbr0 -m comment --comment fwd_filter -j PRE-LIBVIRT',
        'iptables -w -t filter -I FORWARD -i virbr0 -o virbr0 -m comment --comment fwd_filter -j PRE-LIBVIRT',
        'iptables -w -t filter -D FORWARD -i virbr0 -o virbr0 -m comment --comment _pyfwtmp__fwd_filter -j PRE-LIBVIRT',
    ]
































#
