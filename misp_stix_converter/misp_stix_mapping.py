from stix2.v21.common import MarkingDefinition
from typing import Union


class Mapping(dict):
    def __setitem__(self, key, value):
        raise TypeError(f'{type(self).__name__} object does not support item assignment')

    def __delitem__(self, key):
        raise TypeError(f'{type(self).__name__} object does not support item deletion')

    def __getattribute__(self, attribute):
        if attribute in ('clear', 'update', 'pop', 'popitem', 'setdefault'):
            raise AttributeError(f'{type(self).__name__} object has no attribute {attribute}')
        return super().__getattribute__(attribute)


def _tlp2_marking(marking_id: str, name: str, value: str) -> MarkingDefinition:
    return MarkingDefinition(
        id=marking_id,
        created='2022-10-01T00:00:00.000Z',
        name=name,
        extensions={
            'extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d': {
                'extension_type': 'property-extension',
                'tlp_2_0': value
            }
        }
    )


class TLP2MarkingDefinitions:
    _TLP_CLEAR = _tlp2_marking(
        'marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487',
        'TLP:CLEAR', 'clear'
    )
    _TLP_GREEN = _tlp2_marking(
        'marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb',
        'TLP:GREEN', 'green'
    )
    _TLP_AMBER = _tlp2_marking(
        'marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421',
        'TLP:AMBER', 'amber'
    )
    _TLP_AMBER_STRICT = _tlp2_marking(
        'marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003',
        'TLP:AMBER+STRICT', 'amber+strict'
    )
    _TLP_RED = _tlp2_marking(
        'marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1',
        'TLP:RED', 'red'
    )

    __by_uuid = Mapping(
        **{
            _TLP_CLEAR.id: _TLP_CLEAR,
            _TLP_GREEN.id: _TLP_GREEN,
            _TLP_AMBER.id: _TLP_AMBER,
            _TLP_AMBER_STRICT.id: _TLP_AMBER_STRICT,
            _TLP_RED.id: _TLP_RED,
        }
    )
    __by_tag_name = Mapping(
        **{
            'tlp:clear': _TLP_CLEAR,
            'tlp:green': _TLP_GREEN,
            'tlp:amber': _TLP_AMBER,
            'tlp:amber+strict': _TLP_AMBER_STRICT,
            'tlp:red': _TLP_RED,
        }
    )

    @classmethod
    def by_uuid(cls, marking_id: str) -> Union[MarkingDefinition, None]:
        return cls.__by_uuid.get(marking_id)

    @classmethod
    def by_tag_name(cls, tag: str) -> Union[MarkingDefinition, None]:
        return cls.__by_tag_name.get(tag)
