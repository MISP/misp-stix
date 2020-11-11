### MISP to STIX1

#### Summary

| MISP datastructure | STIX object|
| -- | -- |
| Event | `STIX Package` |
| Attribute | `Indicator` or `Observable` in most cases, `TTP`, `Journal entry` or `Custom Object` otherwise |
| Object | `Indicator` or `Observable` in most cases, `TTP`, `Threat Actor`, `Course of Action` or `Custom Object` otherwise |
| Galaxy | `TTP`, `Threat Actor`, or `Course of Action` |

#### Detailed mapping
