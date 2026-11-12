## STIX to MISP

When importing STIX 2.x content into MISP, the converter first determines the origin of the bundle to apply the appropriate parsing strategy:

- **Internal**: The bundle was originally produced by MISP (detected via the `misp:tool="MISP-STIX-Converter"` label on the `Report` or `Grouping` object). The import performs a faithful round-trip, reconstructing MISP attributes, objects, and galaxy clusters from the MISP-specific content: the MISP Extensions in STIX 2.1, the custom objects and properties in STIX 2.0 (see below). The object relations the export folded into property names (`KnownMalicious` travels as `knownmalicious` in STIX 2.1, as `x_misp_knownmalicious` in STIX 2.0) come back with their original spelling and type from the MISP object template pymisp ships, whatever the relation; a property no template nor mapping knows is kept as a `text` attribute under the folded name, and a warning names the object and the property. Galaxy cluster meta keys are free-form, so no template can invert them: the export carries the spelling of every key the fold changed in an `original_names` dictionary (`x_misp_original_names` in STIX 2.0) on the cluster's own STIX object, written only when there is a spelling to carry, and the import reads the keys back from it verbatim (`Capital`, `origin:Storm-0558`, `cfr-type-of-incident`).

- **External**: The bundle was produced by a third-party tool. Standard STIX SDOs and SCOs are mapped to MISP attributes, objects, and galaxies using heuristics. SDOs that represent threat intelligence concepts (`AttackPattern`, `Malware`, `ThreatActor`, etc.) are imported as new MISP Galaxy Clusters.

Both use cases are documented for STIX 2.0 and STIX 2.1 in the sections below.

### MISP content in STIX 2.1 and STIX 2.0

In STIX 2.1, MISP carries the content no standard STIX object or property holds in the [MISP Extensions](#misp-extensions): the `misp-attribute`, `misp-object` and `misp-galaxy-cluster` types, and the MISP Property Extension on standard objects (`knownmalicious`, `original_names`). STIX 2.0 has no extension definitions, so the STIX 2.0 export writes the same content as custom objects (`x-misp-attribute`, `x-misp-object`, `x-misp-galaxy-cluster`) and custom properties (`x_misp_knownmalicious`, `x_misp_original_names`), as the STIX 2.1 export did up to version 2026.10.12.

The import reads both forms, object by object: STIX 2.1 bundles written with custom objects and properties up to version 2026.10.12 still import into the same MISP content.

### Objects whose template name cannot be resolved

A MISP object names the template describing it, and a `misp-object` carries that name in its
`name` property, an `x-misp-object` in its `x_misp_name` property. A name that is not a plain
template name — one holding a path separator, a `..`, or any character a template directory
does not use — is **not** resolved as a template: the object is imported under the name
`unknown-template`, with the name the bundle sent kept in the object's `comment` so nothing is
lost. A name that does resolve is imported exactly as before, custom templates included. The
same applies on export, to the events and objects handed in as JSON: a stored name that cannot
be a template is replaced the same way rather than resolved again.