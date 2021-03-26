# MISP Galaxies to STIX1 mapping

MISP galaxies are exported to STIX as `Course of Action`, `Threat actor` or as one of the different fields embedded within `TTPs`.

Sometimes 2 different Galaxies are mapped into the same STIX1 object, the following examples don't show each Galaxy type, but only one for each resulting STIX object. If you want to see the complete mapping, the [MISP Galaxies to STIX1 mapping summary](README.md#Galaxies-to-STIX1-mapping) gives all the Galaxy types that are mapped into each STIX object type

Since not all the fields of the galaxies and their clusters are exported into STIX1, the following examples are given with the fields that are exported only, if you want to have a look at the full definitions, you can visit the [MISP Galaxies repository](https://github.com/MISP/misp-galaxy).

{_galaxies_to_stix1_mapping_}

## The other detailed mappings

For more detailed mappings, click on one of the link below:
- [Events export to STIX1 mapping](misp_events_to_stix1.md)
- [Attributes export to STIX1 mapping](misp_attributes_to_stix1.md)
- [Objects export to STIX1 mapping](misp_objects_to_stix1.md)

([Go back to the main documentation](README.md))
