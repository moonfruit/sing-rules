from typing import AnyStr, IO

import yaml

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

try:
    from yaml import CDumper as Dumper
except ImportError:
    from yaml import Dumper


def load(stream: AnyStr | IO, loader=Loader):
    """
    Parse the first YAML document in a stream
    and produce the corresponding Python object.
    """
    return yaml.load(stream, loader)


def dump(data, stream: AnyStr | IO = None, dumper=Dumper, **kwargs):
    """
    Parse the first YAML document in a stream
    and produce the corresponding Python object.
    """
    return yaml.dump(data, stream, dumper, **kwargs)
