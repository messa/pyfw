
def zip_dicts(*args):
    all_keys = set()
    for d in args:
        all_keys.update(d.keys())
    rows = []
    for k in sorted(all_keys):
        rows.append((k, ) + tuple(d.get(k) for d in args))
    return rows


assert zip_dicts({}) == []
assert zip_dicts({'foo': 'bar'}) == [('foo', 'bar')]
assert zip_dicts({'foo': 'bar'}, {'foo': 'baz'}) == [('foo', 'bar', 'baz')]
assert zip_dicts({'aa': 11}, {'bb': 22}) == [('aa', 11, None), ('bb', None, 22)]


def zip_sets(*args):
    all_items = set()
    all_items.update(*args)
    rows = []
    for item in sorted(all_items):
        rows.append((item, ) + tuple((item in s) for s in args))
    return rows


assert zip_sets(set(), set()) == []
assert zip_sets({10}, {10}) == [(10, True, True)]
assert zip_sets({10}, {20}) == [(10, True, False), (20, False, True)]
