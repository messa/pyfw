from pprint import pprint

from ..util import zip_dicts


def determine_commands(source_state, desired_state):
    commands = []
    commands.extend(determine_ipsets_commands(source_state.get('ipsets'), desired_state.get('ipsets')))
    commands.extend(determine_iptables_commands(source_state.get('iptables'), desired_state.get('iptables')))
    commands.extend(determine_ip6tables_commands(source_state.get('ip6tables'), desired_state.get('ip6tables')))
    return commands


def determine_ipsets_commands(source_ipsets_state, desired_ipsets_state):
    assert isinstance(source_ipsets_state, dict)
    assert isinstance(desired_ipsets_state, dict)
    for set_name, source_set_state, desired_set_state in \
            zip_dicts(source_ipsets_state, desired_ipsets_state):
        yield from determine_ipsets_set_commands(
            set_name,
            source_set_state,
            desired_set_state)


def determine_ipsets_set_commands(set_name, source_set_state, desired_set_state):
    if not desired_set_state:
        return []
    if not source_set_state:
        yield 'ipset -exist create {name} {typename} {options}'.format(
            name=set_name,
            typename=desired_set_state['type'],
            options=(desired_set_state.get('header') or '')).rstrip()
    source_members = set(source_set_state['members']) if source_set_state else set()
    desired_members = set(desired_set_state['members'])
    for to_remove in sorted(source_members - desired_members):
        yield 'ipset -exist del {name} {member}'.format(name=set_name, member=to_remove)
    for to_add in sorted(desired_members - source_members):
        yield 'ipset -exist add {name} {member}'.format(name=set_name, member=to_add)


def determine_iptables_commands(source_iptables_state, desired_iptables_state):
    for table_name, source_state, desired_state in \
            zip_dicts(source_iptables_state, desired_iptables_state):
        yield from determine_iptables_table_commands(
            table_name, source_state, desired_state)


def determine_iptables_table_commands(table_name, source_table_state, desired_table_state):
    for chain_name, source_state, desired_state in \
            zip_dicts(source_table_state, desired_table_state):
        yield from determine_iptables_chain_commands(
            table_name, chain_name, source_state, desired_state)


def determine_iptables_chain_commands(table_name, chain_name, source_chain_state, desired_chain_state):
    yield from determine_iptables_chain_rule_commands(
        table_name, chain_name,
        source_chain_state.get('rules'),
        desired_chain_state.get('rules'))
    # default action command
    desired_default_action = desired_chain_state['default_action']
    source_default_action = source_chain_state.get('default_action')
    assert desired_default_action
    if desired_default_action != source_default_action:
        yield 'iptables -w -t {table} -P {chain} {action}'.format(
            table=table_name, chain=chain_name, action=desired_default_action)


def determine_ip6tables_commands(source_ip6tables_state, desired_ip6tables_state):
    # TODO
    return []


def determine_iptables_chain_rule_commands(table_name, chain_name, current_rules, target_rules):
    if not target_rules:
        return []
    if current_rules is None:
        current_rules = []

    target_rules = [rule for rule in target_rules if '--comment _pyfw_temp_' not in rule]

    commands = []

    def add_command(op, *args):
        commands.append('iptables -w -t {table} {op} {chain} {args}'.format(
            table=table_name, chain=chain_name,
            op=op, args=' '.join(str(s) for s in args)))

    wip_rules = list(current_rules)

    for pos, rule in enumerate(target_rules):
        if pos >= len(wip_rules):
            add_command('-A', rule)
            wip_rules.append(rule)
            continue

        if rule == wip_rules[pos]:
            continue

        if rule in wip_rules:
            temp_rule = make_temp_rule(rule)
            if commands and commands[-1] != '':
                commands.append('')

            add_command('-I', pos + 1, temp_rule)
            wip_rules.insert(pos, temp_rule)

            for i in range(wip_rules.count(rule)):
                add_command('-D', rule)
                wip_rules.remove(rule)

            add_command('-I', pos + 1, rule)
            wip_rules.insert(pos, rule)

            for i in range(wip_rules.count(temp_rule)):
                add_command('-D', temp_rule)
                wip_rules.remove(temp_rule)

            commands.append('')

        else:
            add_command('-I', pos + 1, rule)
            wip_rules.insert(pos, rule)

            if wip_rules[pos] not in target_rules:
                add_command('-D', wip_rules[pos])
                wip_rules.remove(wip_rules[pos])

    for rule in wip_rules:
        if rule not in target_rules:
            add_command('-D', rule)
            wip_rules.remove(rule)

    while commands and commands[-1] == '':
        commands.pop()

    assert wip_rules == target_rules
    return commands


def make_temp_rule(rule):
    temp_rule = rule.replace('-m comment --comment ', '-m comment --comment _pyfw_temp_')
    if temp_rule == rule:
        temp_rule = '-m comment --comment _pyfw_temp_ ' + rule
    assert temp_rule != rule
    return temp_rule
