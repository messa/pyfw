from textwrap import dedent
import yaml

from pyfw.util import pretty_yaml_dump


_sample_data = {
    'n': 42,
    'f': 3.14159,
    'foo': 'bar',
    'lst': [True, False, 'single line', 'line 1\nline 2\n'],
    'dict': {
        'aa': 'bb',
        'multiline': 'line 1\nline 2\n',
    }
}


def test_yaml_dump():
    out_vanilla = yaml.dump(_sample_data, indent=4, default_flow_style=False)
    assert out_vanilla.strip() == dedent('''
        dict:
            aa: bb
            multiline: 'line 1

                line 2

                '
        f: 3.14159
        foo: bar
        lst:
        - true
        - false
        - single line
        - 'line 1

            line 2

            '
        n: 42
    ''').strip()


def test_pretty_yaml_dump():
    out_pretty = pretty_yaml_dump(_sample_data)
    assert out_pretty.strip() == dedent('''
        dict:
            aa: bb
            multiline: |
                line 1
                line 2
        f: 3.14159
        foo: bar
        lst:
        - true
        - false
        - single line
        - |
            line 1
            line 2
        n: 42
    ''').strip()
