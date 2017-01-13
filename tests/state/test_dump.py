from pytest import skip
import yaml

from pyfw.util import pretty_yaml_dump
from pyfw.state import retrieve_state


def test_dump():
    skip()
    state = retrieve_state()
    state_yaml = pretty_yaml_dump({'state': state})
    print(state_yaml)
    assert 0
