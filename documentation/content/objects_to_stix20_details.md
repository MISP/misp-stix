# MISP Objects to STIX1 mapping

MISP Objects are containers of single MISP attributes that are grouped together to highlight their meaning in a real use case scenario.
For instance, if you want to share a report with suspicious files, without object templates you would end up with a list of file names, hashes, and other attributes that are all mixed together, making the differentiation of each file difficult. In this case with the file object template, we simply group together all the attributes which belong to each file.
The list of currently supported templates is available [here](https://github.com/MISP/misp-objects).

As we can see in the [detailed Events mapping documentation](misp_events_to_stix20.md), objects within their event are exported in different STIX 2.0 objects embedded in a `STIX Bundle`. Those objects' references are also embedded within the report `object_refs` field.  
For the rest of this documentation, we will then, in order to keep the content clear enough and to skip the irrelevant part, consider the followings:
- MISP Objects are exported as Indicator or Observed Data object in most of the cases, depending on the `to_ids` flag:
  - If any `to_ids` flag is set in an object attribute, the object is exported as an Indicator.
  - If no `to_ids` flag is set, the object is exported as an Observed Data
  - Some objects are not exported either as Indicator nor as Observed Data.

### Current mapping

{_objects_to_stix20_mapping_}

### Unmapped object names

Not all the MISP objects are mapped and exported as know STIX 2.0 objects.  
Those unmapped objects are then exported as STIX Custom objects. Here are some examples:
{_custom_objects_to_stix20_mapping_}

## The other detailed mappings

For more detailed mappings, click on one of the link below:
- [Events export to STIX 2.0 mapping](misp_events_to_stix20.md)
- [Attributes export to STIX 2.0 mapping](misp_attributes_to_stix20.md)
- [Galaxies export to STIX 2.0 mapping](misp_galaxies_to_stix20.md)

([Go back to the main documentation](README.md))
