class Mapping(dict):
    def __setitem__(self, key, value):
        raise TypeError(f'{type(self).__name__} object does not support item assignment')

    def __delitem__(self, key):
        raise TypeError(f'{type(self).__name__} object does not support item deletion')

    def __getattribute__(self, attribute):
        if attribute in ('clear', 'update', 'pop', 'popitem', 'setdefault'):
            raise AttributeError(f'{type(self).__name__} object has no attribute {attribute}')
        return super().__getattribute__(attribute)
