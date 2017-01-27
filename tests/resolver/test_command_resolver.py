from collections import defaultdict
import logging
from pprint import pprint
from pytest import skip
import re
from textwrap import dedent
import yaml

from pyfw.parsing import parse_iptables_save
from pyfw.resolver.commands import determine_commands
from pyfw.resolver.commands import determine_iptables_chain_rule_commands


logger = logging.getLogger(__name__)


def test_determine_iptables_chain_rule_commands():
    sample_iptables_save = dedent('''
        # Generated by iptables-save v1.4.21 on Tue Jan 10 15:48:13 2017
        *nat
        :PREROUTING ACCEPT [4:796]
        :INPUT ACCEPT [0:0]
        :OUTPUT ACCEPT [0:0]
        :POSTROUTING ACCEPT [0:0]
        :DOCKER - [0:0]
        -A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
        -A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
        -A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
        -A POSTROUTING -s 172.17.0.2/32 -d 172.17.0.2/32 -p tcp -m tcp --dport 80 -j MASQUERADE
        -A DOCKER -i docker0 -j RETURN
        -A DOCKER ! -i docker0 -p tcp -m tcp --dport 80 -j DNAT --to-destination 172.17.0.2:80
        COMMIT
        # Completed on Tue Jan 10 15:48:13 2017
        # Generated by iptables-save v1.4.21 on Tue Jan 10 15:48:13 2017
        *filter
        :INPUT ACCEPT [889:47280]
        :FORWARD ACCEPT [0:0]
        :OUTPUT ACCEPT [957:99168]
        :DOCKER - [0:0]
        :DOCKER-ISOLATION - [0:0]
        -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
        -A INPUT -p tcp -m tcp --dport 443 -m comment --comment https -j ACCEPT
        -A FORWARD -j DOCKER-ISOLATION
        -A FORWARD -o docker0 -j DOCKER
        -A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        -A FORWARD -i docker0 ! -o docker0 -j ACCEPT
        -A FORWARD -i docker0 -o docker0 -j ACCEPT
        -A FORWARD -d 192.168.122.0/24 -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        -A FORWARD -s 192.168.122.0/24 -i virbr0 -j ACCEPT
        -A FORWARD -i virbr0 -o virbr0 -j ACCEPT
        -A FORWARD -o virbr0 -j REJECT --reject-with icmp-port-unreachable
        -A FORWARD -i virbr0 -j REJECT --reject-with icmp-port-unreachable
        -A FORWARD -p tcp -m set --match-set fwd_allowed_dst_ports dst -m set --match-set fwd_allowed_src_hosts src -m comment --comment allow_vm_fwd -j ACCEPT
        -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment allow_established -j ACCEPT
        -A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT
        -A DOCKER-ISOLATION -j RETURN
        COMMIT
        # Completed on Tue Jan 10 15:48:13 2017
    ''')
    tables = parse_iptables_save(sample_iptables_save)
    chain_state_rules = tables['filter']['FORWARD']['rules']
    chain_desired_rules = [
        '-m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment allow_established -j ACCEPT',
        '-o virbr0 -p tcp -m set --match-set fwd_allowed_dst_ports dst -m set --match-set fwd_allowed_src_hosts src -m comment --comment allow_vm_fwd -j ACCEPT',
        '-o virbr0 -p tcp -m set --match-set fwd_allowed_dst_ports dst -m set ! --match-set fwd_allowed_src_hosts src -m conntrack ! --ctstate RELATED,ESTABLISHED -m comment --comment reject_vm_fwd -j REJECT --reject-with icmp-port-unreachable',
        '-d 192.168.122.0/24 -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
        '-s 192.168.122.0/24 -i virbr0 -j ACCEPT',
        '-i virbr0 -o virbr0 -j ACCEPT',
        '-o virbr0 -j REJECT --reject-with icmp-port-unreachable',
        '-i virbr0 -j REJECT --reject-with icmp-port-unreachable',
        '-j DOCKER-ISOLATION',
        '-o docker0 -j DOCKER',
        '-o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
        '-i docker0 ! -o docker0 -j ACCEPT',
        '-i docker0 -o docker0 -j ACCEPT',
    ]
    commands = determine_iptables_chain_rule_commands('filter', 'FORWARD', chain_state_rules, chain_desired_rules)
    pprint(commands, width=300)
    assert commands == [
        'iptables -w -t filter -I FORWARD 1 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment _pyfw_temp_allow_established -j ACCEPT',
        'iptables -w -t filter -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment allow_established -j ACCEPT',
        'iptables -w -t filter -I FORWARD 1 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment allow_established -j ACCEPT',
        'iptables -w -t filter -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment _pyfw_temp_allow_established -j ACCEPT',
        '',
        'iptables -w -t filter -I FORWARD 2 -o virbr0 -p tcp -m set --match-set fwd_allowed_dst_ports dst -m set --match-set fwd_allowed_src_hosts src -m comment --comment allow_vm_fwd -j ACCEPT',
        'iptables -w -t filter -I FORWARD 3 -o virbr0 -p tcp -m set --match-set fwd_allowed_dst_ports dst -m set ! --match-set fwd_allowed_src_hosts src -m conntrack ! --ctstate RELATED,ESTABLISHED -m comment --comment reject_vm_fwd -j REJECT --reject-with icmp-port-unreachable',
        '',
        'iptables -w -t filter -I FORWARD 4 -m comment --comment _pyfw_temp_ -d 192.168.122.0/24 -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
        'iptables -w -t filter -D FORWARD -d 192.168.122.0/24 -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
        'iptables -w -t filter -I FORWARD 4 -d 192.168.122.0/24 -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
        'iptables -w -t filter -D FORWARD -m comment --comment _pyfw_temp_ -d 192.168.122.0/24 -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
        '',
        'iptables -w -t filter -I FORWARD 5 -m comment --comment _pyfw_temp_ -s 192.168.122.0/24 -i virbr0 -j ACCEPT',
        'iptables -w -t filter -D FORWARD -s 192.168.122.0/24 -i virbr0 -j ACCEPT',
        'iptables -w -t filter -I FORWARD 5 -s 192.168.122.0/24 -i virbr0 -j ACCEPT',
        'iptables -w -t filter -D FORWARD -m comment --comment _pyfw_temp_ -s 192.168.122.0/24 -i virbr0 -j ACCEPT',
        '',
        'iptables -w -t filter -I FORWARD 6 -m comment --comment _pyfw_temp_ -i virbr0 -o virbr0 -j ACCEPT',
        'iptables -w -t filter -D FORWARD -i virbr0 -o virbr0 -j ACCEPT',
        'iptables -w -t filter -I FORWARD 6 -i virbr0 -o virbr0 -j ACCEPT',
        'iptables -w -t filter -D FORWARD -m comment --comment _pyfw_temp_ -i virbr0 -o virbr0 -j ACCEPT',
        '',
        'iptables -w -t filter -I FORWARD 7 -m comment --comment _pyfw_temp_ -o virbr0 -j REJECT --reject-with icmp-port-unreachable',
        'iptables -w -t filter -D FORWARD -o virbr0 -j REJECT --reject-with icmp-port-unreachable',
        'iptables -w -t filter -I FORWARD 7 -o virbr0 -j REJECT --reject-with icmp-port-unreachable',
        'iptables -w -t filter -D FORWARD -m comment --comment _pyfw_temp_ -o virbr0 -j REJECT --reject-with icmp-port-unreachable',
        '',
        'iptables -w -t filter -I FORWARD 8 -m comment --comment _pyfw_temp_ -i virbr0 -j REJECT --reject-with icmp-port-unreachable',
        'iptables -w -t filter -D FORWARD -i virbr0 -j REJECT --reject-with icmp-port-unreachable',
        'iptables -w -t filter -I FORWARD 8 -i virbr0 -j REJECT --reject-with icmp-port-unreachable',
        'iptables -w -t filter -D FORWARD -m comment --comment _pyfw_temp_ -i virbr0 -j REJECT --reject-with icmp-port-unreachable',
        '',
        'iptables -w -t filter -D FORWARD -p tcp -m set --match-set fwd_allowed_dst_ports dst -m set --match-set fwd_allowed_src_hosts src -m comment --comment allow_vm_fwd -j ACCEPT',
    ]


def test_change_default_action():
    source_state = yaml.load(dedent('''
        pyfw_state:
            ipsets: {}
            iptables:
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
    '''))['pyfw_state']
    desired_state = yaml.load(dedent('''
        pyfw_state:
            ipsets: {}
            iptables:
                filter:
                    FORWARD:
                        default_action: ACCEPT
                        rules: []
                    INPUT:
                        default_action: DROP
                        rules:
                        - -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment allow_established -j ACCEPT
                    OUTPUT:
                        default_action: ACCEPT
                        rules: []
    '''))['pyfw_state']
    commands = determine_commands(source_state, desired_state)
    assert commands == [
        'iptables -w -t filter -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment allow_established -j ACCEPT',
        'iptables -w -t filter -P INPUT DROP',
    ]


def test_create_chain():
    source_state = yaml.load(dedent('''
        pyfw_state:
            ipsets: {}
            iptables:
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
    '''))['pyfw_state']
    desired_state = yaml.load(dedent('''
        pyfw_state:
            ipsets: {}
            iptables:
                filter:
                    FORWARD:
                        default_action: ACCEPT
                        rules:
                        - -j FWD_PRE
                    INPUT:
                        default_action: ACCEPT
                        rules: []
                    OUTPUT:
                        default_action: ACCEPT
                        rules: []
                    FWD_PRE:
                        default_action: '-'
                        rules:
                        - '! -i docker0 -o docker0 -m set ! --match-set allowed_hosts src -m comment --comment allowed_hosts_only -j REJECT --reject-with icmp-port-unreachable'

    '''))['pyfw_state']
    commands = determine_commands(source_state, desired_state)
    assert commands == [
        'iptables -w -t filter -N FWD_PRE',
        'iptables -w -t filter -A FORWARD -j FWD_PRE',
        'iptables -w -t filter -A FWD_PRE ! -i docker0 -o docker0 -m set ! --match-set allowed_hosts src -m comment --comment allowed_hosts_only -j REJECT --reject-with icmp-port-unreachable',
    ]
