# STIX 2.0 to MISP Objects mapping

MISP Objects are containers grouping related MISP attributes. When importing STIX 2.0 content, composite STIX structures (an `Indicator` with a multi-field pattern, or an `Observed Data` with multiple observable objects) are mapped to the corresponding MISP object template.

The list of currently supported MISP object templates is available [here](https://github.com/MISP/misp-objects).

### Current mapping

{_objects_from_stix20_mapping_}

## The other detailed mappings

- [Attributes mapping](stix20_to_misp_attributes.md)
