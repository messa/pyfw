from collections import defaultdict
from pprint import pprint
import re

from ..util import zip_dicts


def determine_desired_state(source_state, wishes):
    return {
        'iptables': _desired_iptables_state(source_state.get('iptables'), wishes.get('iptables')),
        'ip6tables': _desired_ip6tables_state(source_state.get('ip6tables'), wishes.get('ip6tables')),
        'ipsets': _desired_ipsets_state(source_state.get('ipsets'), wishes.get('ipsets')),
    }


def _desired_ipsets_state(ipsets_state, ipsets_wishes):
    if not ipsets_wishes:
        return ipsets_state
    assert isinstance(ipsets_state, dict)
    assert isinstance(ipsets_wishes, dict)
    desired_ipsets_state = {}
    for set_name, set_state, set_wishes in zip_dicts(ipsets_state, ipsets_wishes):
        desired_ipsets_state[set_name] = _desired_ipsets_set_state(set_state, set_wishes)
    return desired_ipsets_state


def _desired_ipsets_set_state(set_state, set_wishes):
    if not set_wishes:
        return set_state
    return {
        'type': set_wishes['type'],
        'header': set_wishes.get('header'),
        'members': set_wishes['members_equal'],
    }


def _desired_ip6tables_state(ip6tables_state, ip6tables_wishes):
    # TODO
    return ip6tables_state


def _desired_iptables_state(iptables_state, iptables_wishes):
    if not iptables_state or not iptables_wishes:
        return iptables_state
    assert isinstance(iptables_state, dict)
    assert isinstance(iptables_wishes, dict)
    desired_iptables_state = {}
    for table_name, table_state, table_wishes in zip_dicts(iptables_state, iptables_wishes):
        desired_iptables_state[table_name] = _desired_iptables_table_state(
            table_name, table_state, table_wishes)
    return desired_iptables_state


def _desired_iptables_table_state(table_name, table_state, table_wishes):
    if not table_wishes:
        assert isinstance(table_state, dict)
        return table_state
    chain_names = table_state.keys() | table_wishes.keys()
    return {ch: determine_desired_chain_state(
        table_state.get(ch), table_wishes.get(ch)) for ch in sorted(chain_names)}


def determine_desired_chain_state(chain_state, chain_wishes):
    if not chain_wishes:
        return chain_state
    return {
        'default_action': determine_desired_chain_default_action(chain_state.get('default_action'), chain_wishes.get('default_action')),
        'rules': determine_desired_chain_rules(chain_state.get('rules'), chain_wishes.get('rules')),
    }


def determine_desired_chain_default_action(state_action, wish_action):
    if not wish_action:
        return state_action
    else:
        return wish_action


def determine_desired_chain_rules(rules, wishes):
    if not wishes:
        return rules

    desired_rules = []

    rules_by_comment = defaultdict(list) # str -> [str]
    for rule in rules:
        m = re.search(r'(?:^| )-m comment --comment (?P<comment>[a-zA-z0-9_-]+)(?: |$)', rule)
        if m:
            comment = m.group('comment')
            rules_by_comment[comment].append(rule)

    remaining_rules = list(rules)

    for wish in wishes:
        if isinstance(wish, dict):
            (w_key, w_value), = wish.items()
            assert isinstance(w_key, str)
            if w_key.startswith('~'):
                if w_key == '~match':
                    assert isinstance(w_value, str)
                    matched_rules = [rule for rule in remaining_rules if re.search(w_value, rule)]
                    desired_rules.extend(matched_rules)
                    for rule in matched_rules:
                        remaining_rules.remove(rule)
                else:
                    raise Exception('Key starts with "~" but is not "~match"')
            else:
                assert isinstance(w_value, str)
                desired_rules.append(w_value)
                for rule in rules_by_comment[w_key]:
                    remaining_rules.remove(rule)
        else:
            raise Exception('Expected to be dict: {!r}'.format(wish))

    desired_rules.extend(remaining_rules)
    return desired_rules
