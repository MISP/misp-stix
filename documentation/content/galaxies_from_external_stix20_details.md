# External STIX 2.0 to MISP Galaxies mapping

When importing STIX 2.0 bundles from third-party tools (not produced by MISP), SDOs such as `Attack Pattern`, `Campaign`, `Course of Action`, `Intrusion Set`, `Malware`, `Threat Actor`, `Tool` and `Vulnerability` are imported as MISP Galaxy Clusters with a dynamically generated galaxy type of the form `stix-2.0-{{object-type}}`.

Unlike the internal conversion (which maps back to known MISP galaxy types), the external conversion creates new `STIX 2.0 *` galaxies that preserve the original STIX content. The cluster value is the STIX object's `name`, and meta fields are extracted from fields such as `aliases`, `kill_chain_phases`, `external_references`, etc.

As an exception, an `Identity` whose `identity_class` is `class` is mapped to the existing MISP `sector` galaxy rather than a dynamically generated `stix-2.0-*` type.

{_external_galaxies_from_stix20_mapping_}

## The other detailed mappings

For more detailed mappings, click on one of the links below:
- [Attributes import from STIX 2.0 mapping](stix20_to_misp_attributes.md)
- [Objects import from STIX 2.0 mapping](stix20_to_misp_objects.md)

([Go back to the main documentation](README.md))
