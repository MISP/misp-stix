# MISP Objects to STIX1 mapping

MISP Objects are containers of single MISP attributes that are grouped together to highlight their meaning in a real use case scenario.  
For instance, if you want to share a report with suspicious files, without object templates you would end up with a list of file names, hashes, and other attributes that are all mixed together, making the differentiation of each file difficult. In this case with the file object template, we simply group together all the attributes which belong to each file.  
The list of currently supported templates is available [here](https://github.com/MISP/misp-objects).

As we can see in the [detailed Events mapping documentation](misp_events_to_stix1.md), objects within their event are exported in different STIX objects embedded in a `STIX Package`. Indicators and observables are also embedded in the `Incident` but it is not the case for TTPS for instance.  
So for he rest of this documentation, in order to keep the content clear enough and to skip the irrelevant part, we will consider the followings:
- Indicators and observables are displayed as standalone objects, but we keep in mind that **if the related MISP objects are exported within their event, those STIX objects are actually exported within their Incident and STIX Package**
- We will give details about the context of each STIX object being neither an Indicator not an Observable case by case, since those ones are also displayed outside of their Incident or STIX package.
- In the following examples, every MISP object that has at least one attribute with a `to_ids` flag is exported within an indicator, but in any case the object attributes are contained in an observable object.
- More details given about the `to_ids` flag if necessary, case by case

### Current mapping

{_objects_to_stix1_mapping_}

### Unmapped objects

As for attributes, the variety of available MISP object templates is larger than the STIX scope, which makes it impossible to map every MISP object to a specific STIX object.  
Again we do not skip those pieces of data and export them as `Custom` objects instead. Let us see some examples of custom objects exported from MISP objects:
{_custom_objects_to_stix1_mapping_}

## The other detailed mappings

For more detailed mappings, click on one of the link below:
- [Events mapping](misp_events_to_stix1.md)
- [Attributes mapping](misp_attributes_to_stix1.md)
- [Galaxies mapping](misp_galaxies_to_stix1.md)

([Go back to the main documentation](README.md))
