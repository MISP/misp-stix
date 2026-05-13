# External STIX 2.1 to MISP Attributes mapping

When importing external STIX 2.1 content (bundles not produced by MISP) into MISP, `Indicator` objects are parsed to produce MISP attributes with the `to_ids` flag set, while `Observed Data` objects (with their referenced SCOs) or standalone SCOs produce MISP attributes with the `to_ids` flag unset.

External STIX objects are mapped to the closest MISP attribute type via heuristics.

### Current mapping

{_external_attributes_from_stix21_mapping_}

## The other detailed mappings

- [External Objects mapping](external_stix21_to_misp_objects.md)
