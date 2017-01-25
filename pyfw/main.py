import argparse
import difflib
import logging
import os
from pathlib import Path
import subprocess
import sys
import yaml

from .state import retrieve_state
from .util import pretty_yaml_dump
from .resolver import determine_desired_state, determine_commands


__version__ = '0.1.4'

default_wishes_file = '/etc/pyfw/wishes.yaml'


def pyfw_main():
    p = argparse.ArgumentParser()
    p.add_argument('--version', action='store_true', help='show version info and exit')
    p.add_argument('--use-state', help='load state from file instead of inquiring OS')
    p.add_argument('--print-state', action='store_true', help='just print the state')
    p.add_argument('--print-desired-state', action='store_true', help='just print the computed desired state (state + wishes)')
    p.add_argument('--print-state-diff', action='store_true', help='just print the difference between state and computed desired state')
    p.add_argument('--apply', action='store_true', help='execute the commands')
    p.add_argument('--wishes', default=default_wishes_file,
        help='YAML file with your wishes, default: {}'.format(default_wishes_file))
    args = p.parse_args()

    if args.version:
        print('pyfw version {} in {}'.format(__version__, Path(__file__).parent))
        sys.exit()

    logging.basicConfig(
        format='%(message)s',
        level=logging.INFO)

    if args.use_state:
        with open(args.use_state) as f:
            state = yaml.safe_load(f)['state']
        real_state_before = None
    else:
        try:
            state = retrieve_state()
        except Exception as e:
            sys.exit('Failed to retrieve current state: {}'.format(e))
        real_state_before = state

    if args.print_state:
        print(pretty_yaml_dump({'pyfw_state': state}), end='')
        return

    with open(args.wishes) as f:
        wishes = yaml.safe_load(f)['pyfw_wishes']

    desired_state = determine_desired_state(state, wishes)

    if args.print_desired_state:
        print(pretty_yaml_dump({'pyfw_state': desired_state}), end='')

    if args.print_state_diff:
        sys.stdout.writelines(difflib.unified_diff(
            pretty_yaml_dump({'state': state}).splitlines(True),
            pretty_yaml_dump({'state': desired_state}).splitlines(True),
            fromfile='state.yaml',
            tofile='desired_state.yaml', n=5))

    if args.print_desired_state or args.print_state_diff:
        return

    commands = determine_commands(state, desired_state)

    if args.apply:

        if args.use_state:
            print('You are about to apply commands derived from state given in file.')

        if not commands:
            print('All wished already fullfilled.')
        else:
            if not real_state_before:
                real_state_before = retrieve_state()

            for n, cmd in enumerate(commands, start=1):
                print('Executing command {:2d}/{}: {}'.format(n, len(commands), cmd))
                subprocess.check_call(cmd, shell=True)

            real_state_after = retrieve_state()

            print()
            print('State change:')
            print()
            sys.stdout.writelines(difflib.unified_diff(
                pretty_yaml_dump({'pyfw_state': real_state_before}).splitlines(True),
                pretty_yaml_dump({'pyfw_state': real_state_after}).splitlines(True),
                fromfile='state_before.yaml',
                tofile='real_state_after.yaml', n=5))

    else:
        if not commands:
            print('# no commands needed, all wished fullfilled')
        else:
            print('# these commands should fullfill all given wishes:')
            for cmd in commands:
                print(cmd)
