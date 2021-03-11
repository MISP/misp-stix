# MISP Attributes to STIX 2.1 mapping

MISP Attributes are the actual raw data used by analysts to describe the IoCs and observed data related to a specific event (which could be an actual threat report, an IP watchlist, etc.)
Thus, in most of the cases, a MISP Attribute is exported to STIX as `Indicator` if its `to_ids` flag is set, or as `Observable` if its `to_ids` flag is false. But there are also some other examples where MISP attributes are exported neither as indicator nor as observable, this documentation gives all the details about the single attributes mapping into STIX objects, depending on the type of the attributes.

As we can see in the [detailed Events mapping documentation](misp_events_to_stix21.md), attributes within their event are exported in different STIX 2.1 objects embedded in a `STIX Bundle`. Those objects' references are also embedded within the Report or Grouping `object_refs` field.  
For the rest of this documentation, we will then, in order to keep the content clear enough and to skip the irrelevant part, consider the followings:
- Attributes are exported as Indicator or Observed Data objects in most of the cases
- In the following examples, attributes are shown as example withtout their `to_ids` flag
  - An Indicator means the attribute is exported with the `to_ids` flag set to `True`
  - An Observed Data means the attribute is exported with the `to_ids` flag unset (`False`)
  - If neither an Indicator nor an Observed Data object is documented for a given attribute, the `to_ids` flag does not matter

### Current mapping

{_attributes_to_stix21_mapping_}

### Unmapped attribute types

You may have noticed we are very far from having all the attribute types supported. This is due to the various use cases that MISP can be used for.  
Nonetheless, every attribute whose type is not in the list, is exported as `Custom` object.  
With the following examples, `btc` and `iban` are attribute types that are not mapped, where the other ones:
- are already mentioned above and giving valid STIX 2.1 pattern expressions when their `to_ids` flag is set to `True`.
- are not providing enough information to produce Observable objects and are then exported as `Custom` objects when their `to_ids` flag is unset.

Let us see those examples of custom objects exported from attributes:
{_custom_attributes_to_stix21_mapping_}

## The other detailed mappings

For more detailed mappings, click on one of the link below:
- [Events export to STIX 2.1 mapping](misp_events_to_stix21.md)
- [Objects export to STIX 2.1 mapping](misp_objects_to_stix21.md)
- [Galaxies export to STIX 2.1 mapping](misp_galaxies_to_stix21.md)

([Go back to the main documentation](README.md))
