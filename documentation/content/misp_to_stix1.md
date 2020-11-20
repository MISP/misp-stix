### MISP to STIX1

#### Events mapping

##### Summary

| MISP datastructure | STIX object|
| -- | -- |
| Event | `STIX Package` |
| Attribute | `Indicator` or `Observable` in most cases, `TTP`, `Journal entry` or `Custom Object` otherwise |
| Object | `Indicator` or `Observable` in most cases, `TTP`, `Threat Actor`, `Course of Action` or `Custom Object` otherwise |
| Galaxy | `TTP`, `Threat Actor`, or `Course of Action` |

##### Detailed mapping

The detailed mapping for events and its contained structures, with explanations and examples, is available [here](misp_events_to_stix1.md)

#### Attributes mapping

##### Summary

| MISP Attribute | STIX Observable object type |
| -- | -- |

##### Detailed mapping

The detailed mapping for attributes, with explanations and examples, is available [here](misp_attributes_to_stix1.md)
