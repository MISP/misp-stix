# External STIX 2.1 to MISP Objects mapping

MISP Objects are containers grouping related MISP attributes. When importing external STIX 2.1 content (bundles not produced by MISP), composite STIX structures (an `Indicator` with a multi-field pattern, or an `Observed Data` with referenced SCOs, or standalone SCOs) are mapped to the corresponding MISP object template.

The list of currently supported MISP object templates is available [here](https://github.com/MISP/misp-objects).

### Current mapping

{_external_objects_from_stix21_mapping_}

## The other detailed mappings

- [External Attributes mapping](external_stix21_to_misp_attributes.md)
