import yaml


def pretty_yaml_dump(data, indent=4, width=200):
    data_tr = transform(data)
    return yaml.dump(data_tr, indent=indent, width=width, default_flow_style=False)


class MultilineStr:

    __slots__ = ('content', )

    def __init__(self, content):
        self.content = content

    def __repr__(self):
        import reprlib
        return '<{cls} {s}>'.format(
            cls=self.__class__.__name__,
            s=reprlib.repr(self.content))


def multiline_str_representer(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data.content, style='|')


yaml.add_representer(MultilineStr, multiline_str_representer)


def transform(obj):
    if isinstance(obj, dict):
        return {k: transform(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [transform(v) for v in obj]
    elif isinstance(obj, str):
        if '\n' in obj:
            return MultilineStr(obj)
        else:
            return obj
    else:
        return obj
