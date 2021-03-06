from pprint import pprint
from textwrap import dedent

from pyfw.parsing import parse_iptables_save


sample_dump = dedent('''
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
    -A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT
    -A DOCKER-ISOLATION -j RETURN
    COMMIT
    # Completed on Tue Jan 10 15:48:13 2017
''')


def test_parse_iptables_save():
    tables = parse_iptables_save(sample_dump)
    assert tables == {
        'nat': {
            'DOCKER': {
                'default_action': '-',
                'rules': [
                    '-i docker0 -j RETURN',
                    '! -i docker0 -p tcp -m tcp --dport 80 -j DNAT --to-destination 172.17.0.2:80']},
            'INPUT': {
                'default_action': 'ACCEPT', 'rules': []},
            'OUTPUT': {
                'default_action': 'ACCEPT',
                'rules': [
                    '! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER']},
            'POSTROUTING': {
                'default_action': 'ACCEPT',
                'rules': [
                    '-s 172.17.0.0/16 ! -o docker0 -j MASQUERADE',
                    '-s 172.17.0.2/32 -d 172.17.0.2/32 -p tcp -m tcp --dport 80 -j MASQUERADE']},
            'PREROUTING': {
                'default_action': 'ACCEPT',
                'rules': [
                    '-m addrtype --dst-type LOCAL -j DOCKER']}},
        'filter': {
            'DOCKER': {
                'default_action': '-',
                'rules': [
                    '-d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT',
                ]},
            'DOCKER-ISOLATION': {
                'default_action': '-',
                'rules': ['-j RETURN']
            },
            'FORWARD': {
                'default_action': 'ACCEPT',
                'rules': [
                    '-j DOCKER-ISOLATION',
                    '-o docker0 -j DOCKER',
                    '-o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
                    '-i docker0 ! -o docker0 -j ACCEPT',
                    '-i docker0 -o docker0 -j ACCEPT']},
            'INPUT': {
                'default_action': 'ACCEPT',
                'rules': [
                    '-p tcp -m tcp --dport 80 -j ACCEPT',
                    '-p tcp -m tcp --dport 443 -m comment --comment https -j ACCEPT']},
            'OUTPUT': {'default_action': 'ACCEPT', 'rules': []}},
    }
