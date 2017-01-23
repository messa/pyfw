import logging
import os
import subprocess


logger = logging.getLogger(__name__)


def get_output(cmd):
    return subprocess.check_output(cmd, universal_newlines=True)


def retrieve_state():
    from pyfw.parsing import parse_iptables_save, parse_ipset_list
    # just list - this causes to modprobe if kernel modules not loaded yet
    get_output(['iptables', '-L'])
    get_output(['ip6tables', '-L'])
    iptables_save = get_output(['iptables-save'])
    ip6tables_save = get_output(['ip6tables-save'])
    if not iptables_save.strip():
        raise Exception('Output if iptables-save is empty')
    if not ip6tables_save.strip():
        raise Exception('Output if ip6tables-save is empty')
    ipset_list = get_output(['ipset', 'list'])
    return {
        'iptables': parse_iptables_save(iptables_save),
        'ip6tables': parse_iptables_save(ip6tables_save),
        'ipsets': parse_ipset_list(ipset_list),
    }
