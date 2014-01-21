'''Helper module for py2/py3k'''


def add_metaclass(metaclass):
    """Class decorator for creating a class with a metaclass."""
    # Taken from six.py
    def wrapper(cls):
        orig_vars = cls.__dict__.copy()
        orig_vars.pop('__dict__', None)
        orig_vars.pop('__weakref__', None)
        for slots_var in orig_vars.get('__slots__', ()):
            orig_vars.pop(slots_var)
        return metaclass(cls.__name__, cls.__bases__, orig_vars)
    return wrapper
