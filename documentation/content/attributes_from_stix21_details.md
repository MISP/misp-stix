# STIX 2.1 to MISP Attributes mapping

When importing STIX 2.1 content into MISP, `Indicator` objects are parsed to produce MISP attributes with the `to_ids` flag set, while `Observed Data` objects (together with their referenced SCOs) produce MISP attributes with the `to_ids` flag unset.

For internally-generated STIX bundles (i.e. bundles produced by MISP), the mapping is a faithful round-trip: the original MISP attribute type and value are recovered from the STIX pattern or observable.

For externally-generated STIX bundles, STIX objects are mapped to the closest MISP attribute type via heuristics.

### Current mapping

{_attributes_from_stix21_mapping_}

## The other detailed mappings

- [Objects mapping](stix21_to_misp_objects.md)
