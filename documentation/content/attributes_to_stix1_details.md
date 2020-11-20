# Attributes mapping

In most of the cases, a MISP Attribute is exported to STIX as `Indicator` if its `to_ids` flag is set, or as `Observable` if its `to_ids` flag is false.But there are also some other examples where none of those two situations happen. This documentation gives all the details about the single attributes mapping into STIX objects, depending on the type of the attributes.

As we can see in the [detailed Events mapping documentation](misp_events_to_stix1.md), attributes within their event are exported in different STIX objects embedded in a `STIX Package`. Indicators and observables are also embedded in the `Incident` but it is not the case for TTPS for instance.  
So fot he rest of this documentation, in order to keep the content clear enough and to skip the irrelevant part, we will consider the followings:
- Indicators and observables are displayed as standalone objects, but we keep in mind that **if the related MISP attributes are exported within their event, those STIX objects are actually exported within their Incident and STIX Package**
- We will give details about the context of each STIX object being neither an Indicator not an Observable case by case, since those ones are also displayed outside of their Incident or STIX package.
- In the following examples, every MISP attribute that has a `to_ids` flag, has the default value for this flag, depending on the attribute type.
- Switching the `to_ids` flag value would simply change the result from Indicator to Observable or from Observable to indicator
- More details given about the `to_ids` flag if necessary, case by case

{_attributes_to_stix1_mapping_}

## The other detailed mappings

For more detailed mappings, click on one of the link below:
- [Events mapping](misp_events_to_stix1.md)
- [Objects mapping](misp_objects_to_stix1.md)
- [Galaxies mapping](misp_galaxies_to_stix1.md)

([Go back to the main documentation](README.md))
