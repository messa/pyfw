import re


re_chain = re.compile(r'^:(?P<chain_name>[A-Z0-9_-]+) (?P<default_action>ACCEPT|DROP|-) \[[0-9:]*\]$')
re_rule = re.compile(r'^-A (?P<chain_name>[A-Z0-9_-]+) (?P<rule_args>.+)$')


def parse_iptables_save(dump):
    '''
    Parses output of iptables-save into a structure of tables, chains and rules.
    For example see test_parse_iptables_save.
    '''
    tables = {}
    current_table = None

    for n, line in enumerate(dump.splitlines(), start=1):
        try:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if line.startswith('*'):
                table_name = line[1:]
                current_table = {}
                assert table_name not in tables
                tables[table_name] = current_table
                continue

            if line.startswith(':'):
                m = re_chain.match(line)
                if not m:
                    raise Exception('Failed to parse :CHAIN line')
                name = m.group('chain_name')
                assert name not in current_table
                current_table[name] = {
                    'default_action': m.group('default_action'),
                    'rules': [],
                }
                continue

            if line.startswith('-A '):
                m = re_rule.match(line)
                if not m:
                    raise Exception('Failed to parse -A line')
                current_table[m.group('chain_name')]['rules'].append(m.group('rule_args'))
                continue

            if line == 'COMMIT':
                current_table = None
                continue

            raise Exception('Unknown line content')

        except Exception as e:
            raise Exception('Line {}: {}; full line: {!r}'.format(n, e, line))

    return tables


def parse_ipset_list(dump):
    ipsets = {}
    current_ipset = None
    in_members = False

    for n, line in enumerate(dump.splitlines(), start=1):
        try:
            line = line.strip()

            if in_members:
                if not line:
                    in_members = False
                    current_ipset = None
                else:
                    current_ipset['members'].append(line)
                continue

            if not line or line.startswith('#'):
                continue

            m = re.match(r'^Name: (.+)$', line)
            if m:
                name = m.group(1)
                current_ipset = {
                    'type': None,
                    'header': None,
                    'members': [],
                }
                assert name not in ipsets
                ipsets[name] = current_ipset
                continue

            m = re.match(r'^Type: (.+)$', line)
            if m:
                current_ipset['type'] = m.group(1)
                continue

            m = re.match(r'Header: (.+)$', line)
            if m:
                current_ipset['header'] = m.group(1)
                continue

            if line == 'Members:':
                in_members = True
                continue

            if ':' in line:
                continue

            raise Exception('Unknown line content')

        except Exception as e:
            raise Exception('Line {}: {}; full line: {!r}'.format(n, e, line))

    return ipsets
