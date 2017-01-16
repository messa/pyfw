import logging


logger = logging.getLogger(__name__)


def determine_commands(state, wishes):
    '''
    Returns a list of commands (strings).
    '''
    commands = []

    def add_cmd(cmd):
        assert isinstance(cmd, str)
        logger.debug('Command: %s', cmd)
        commands.append(cmd)

    _DetermineIptablesCommands(state, wishes).run(add_cmd)
    _DetermineIpsetsCommands(state, wishes).run(add_cmd)
    return commands


class _DetermineIpsetsCommands:

    def __init__(self, state, wishes):
        self.state = state
        self.wishes = wishes

    def run(self, add_cmd):
        ipsets_wishes = self.wishes.get('ipsets')
        if not ipsets_wishes:
            return

        for ipset_name, ipset_wish in sorted(ipsets_wishes.items()):
            self.process_ipset_wish(add_cmd, ipset_name, ipset_wish)

    def process_ipset_wish(self, add_cmd, ipset_name, ipset_wish):
        logger.debug('Processing ipsets.%s', ipset_name)
        ipset_state = self.state['ipsets'].get(ipset_name)
        if not ipset_state:
            add_cmd('ipset -exist create {name} {typename} {options}'.format(
                name=ipset_name,
                typename=ipset_wish['type'],
                options=ipset_wish.get('header', '')).rstrip())

        state_members = set(ipset_state['members']) if ipset_state else set()

        if ipset_wish.get('members_equal'):
            wish_members = set(ipset_wish['members_equal'])
            for to_remove in (state_members - wish_members):
                add_cmd('ipset -exist del {name} {member}'.format(name=ipset_name, member=to_remove))
            for to_add in (wish_members - state_members):
                add_cmd('ipset -exist add {name} {member}'.format(name=ipset_name, member=to_add))


class _DetermineIptablesCommands:

    allowed_iptables_table_names = 'filter nat mangle'.split()

    def __init__(self, state, wishes):
        self.state = state
        self.wishes = wishes

    def run(self, add_cmd):
        iptables_wishes = self.wishes.get('iptables')
        if not iptables_wishes:
            return

        for table, t_data in sorted(iptables_wishes.items()):
            self.check_iptables_table_name(table)
            for chain, ch_data in sorted(t_data.items()):
                self.check_iptables_chain_name(table, chain)
                if not isinstance(ch_data, list):
                    raise Exception('Expected iptables.{}.{} to be a list'.format(table, chain))

                for n, rule_wish in enumerate(ch_data):
                    if not isinstance(rule_wish, dict) or len(rule_wish) != 1:
                        raise Exception('Expected iptables.{}.{}[{}] to be a single-item dictionary'.format(table, chain, n))
                    item, = rule_wish.items()
                    rule_name, rule_data = item
                    self.process_iptables_wish(add_cmd, table, chain, n, rule_name, rule_data)

    def check_iptables_table_name(self, table):
        if table not in self.allowed_iptables_table_names:
            raise Exception(
                'Unknown iptables table name: {!r}; allowed names: {}'.format(
                    table, self.allowed_iptables_table_names))

    def check_iptables_chain_name(self, table, chain):
        if chain != chain.upper():
            raise Exception(
                'Chain name {!r} is not uppercase (in iptables table {!r})'.format(
                    chain, table))

    def process_iptables_wish(self, add_cmd, table, chain, n, rule_name, rule_data):
        logger.debug(
            'Processing iptables.%s.%s[%s] %r: %r',
            table, chain, n, rule_name, rule_data)

        wish_rule = rule_data['rule']
        before_another_rule = rule_data.get('before')

        state_all_rules = self.state['iptables'][table][chain]['rules']
        state_matching_rules = self.find_matching_rules(state_all_rules, rule_name)

        if len(state_matching_rules) > 1:
            logger.warning(
                'There are multiple matching rules for comment %r, they will be all replaced: %r',
                rule_name, state_matching_rules)
            self.replace_iptables_rules(
                add_cmd, table, chain,
                state_matching_rules, wish_rule, insert=before_another_rule)

        else:
            if state_matching_rules:
                state_matching_rule, = state_matching_rules
                logger.debug('Matching rule in state: %r', state_matching_rule)
            else:
                logger.debug('No matching rule in state')
                state_matching_rule = None

            if not state_matching_rule:
                self.create_iptables_rule(
                    add_cmd, table, chain,
                    wish_rule, insert=before_another_rule)

            elif state_matching_rule == wish_rule:
                logger.debug('State rule == wish rule args')

                if before_another_rule:
                    # zkontrolovat, že tato rule je před
                    self.reorder_iptables_rule_if_needed(
                        add_cmd, table, chain,
                        wish_rule, before_another_rule, state_all_rules)

            else:
                logger.debug('State rule != wish rule, will be replaced')
                self.replace_iptables_rules(
                    add_cmd, table, chain,
                    [state_matching_rule], wish_rule,  insert=before_another_rule)


    def reorder_iptables_rule_if_needed(self, add_cmd, table, chain, wish_rule, before_another_rule, state_all_rules):
        assert isinstance(wish_rule, str)
        assert isinstance(before_another_rule, str)
        assert all(isinstance(r, str) for r in state_all_rules)
        wish_rule_position = None
        before_another_rule_position = None
        for n, rule in enumerate(state_all_rules):
            if rule == wish_rule:
                wish_rule_position = n
            elif before_another_rule in rule:
                before_another_rule_position = n
        if wish_rule_position is None:
            raise Exception('Could not find wish rule position')
        if before_another_rule_position is None:
            logger.debug('Before another rule position not found')
        else:
            if before_another_rule_position < wish_rule_position:
                logger.debug('Need to reorder')
                self.replace_iptables_rules(
                    add_cmd, table, chain,
                    [wish_rule], wish_rule, insert=True)

    def replace_iptables_rules(self, add_cmd, table, chain, current_rules, new_rule, insert):
        # create temporary rule
        new_rule_temp = self.add_temp_prefix(new_rule)
        self.create_iptables_rule(add_cmd, table, chain, new_rule_temp, insert=insert)

        # remove old rule(s)
        for rule in current_rules:
            self.remove_iptables_rule(add_cmd, table, chain, rule)

        # create new rule
        self.create_iptables_rule(add_cmd, table, chain, new_rule, insert=insert)

        # remove temporary rule
        self.remove_iptables_rule(add_cmd, table, chain, new_rule_temp)

    def create_iptables_rule(self, add_cmd, table, chain, wish_rule, insert):
        add_cmd('iptables -w -t {table} -{x} {chain} {args}'.format(
            table=table, chain=chain, args=wish_rule,
            x='I' if insert else 'A'))

    def remove_iptables_rule(self, add_cmd, table, chain, rule):
        add_cmd('iptables -w -t {table} -D {chain} {rule}'.format(
            table=table, chain=chain, rule=rule))

    def find_matching_rules(self, rules, comment):
        matching_rules = []
        search_str = '-m comment --comment ' + comment
        for rule in rules:
            assert isinstance(rule, str)
            if rule.endswith(search_str) or (search_str + ' ') in rule:
                matching_rules.append(rule)
        return matching_rules

    def add_temp_prefix(self, rule):
        assert isinstance(rule, str)
        temp_rule = rule.replace(' --comment ', ' --comment _pyfwtmp__', 1)
        if temp_rule == rule:
            raise Exception('Failed to add temp prefix')
        logger.debug('Temp prefix: %r -> %r', rule, temp_rule)
        return temp_rule
