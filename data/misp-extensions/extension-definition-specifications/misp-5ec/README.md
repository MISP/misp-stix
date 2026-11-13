# MISP Extensions for STIX 2.1

Version 1.0.0

## Abstract

The MISP Extensions carry in STIX 2.1 the MISP content that no standard STIX object or property
holds: the MISP attributes, objects and galaxy clusters no standard STIX object represents, and,
on standard STIX objects, the MISP values their standard properties leave over. The MISP-STIX
converter ([`misp-stix`](https://github.com/MISP/misp-stix)) writes them in its STIX 2.1 export
and reads them back in its import, so a MISP event goes through STIX 2.1 and back to MISP whole.

This document describes the four extension definitions, following the STIX Extension Definition
Policy (section 3.3). The JSON schemas in this directory are their normative definition; where
this document and a schema disagree, the schema wins.

## Table of Contents

1. [Introduction](#1-introduction)
2. [MISP Property Extension](#2-misp-property-extension)
3. [MISP Attribute Extension](#3-misp-attribute-extension)
4. [MISP Object Extension](#4-misp-object-extension)
5. [MISP Galaxy Cluster Extension](#5-misp-galaxy-cluster-extension)
6. [Bundles](#6-bundles)
7. [Conformance Notes](#7-conformance-notes)
8. [Examples](#8-examples)
9. [Appendix A. The Custom Syntax](#appendix-a-the-custom-syntax)

## 1. Introduction

### 1.1 Document Conventions

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**",
"**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and
"**OPTIONAL**" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174]
when, and only when, they appear in all capitals, as shown here.

Property names are in **bold**. Type names, literals and STIX object types are in `monospace`.
The property types are the STIX 2.1 data types (STIX 2.1, section 2), plus the *value* this
document defines in [section 2.3](#23-values). Section numbers prefixed with "STIX 2.1" refer to
the STIX Version 2.1 specification.

### 1.2 Overview

There are four MISP Extensions, one per kind of MISP content:

| Name | Extension type | Extension definition id | Schema |
| -- | -- | -- | -- |
| MISP Attribute Extension | `new-sdo` | `extension-definition--c1f2c0fa-3786-4f27-bf57-cf050ecfc104` | [`misp-attribute/…`](misp-attribute/extension-definition--c1f2c0fa-3786-4f27-bf57-cf050ecfc104.json) |
| MISP Object Extension | `new-sdo` | `extension-definition--a093107b-933f-4d72-a9a6-6d7318adadda` | [`misp-object/…`](misp-object/extension-definition--a093107b-933f-4d72-a9a6-6d7318adadda.json) |
| MISP Galaxy Cluster Extension | `new-sdo` | `extension-definition--573a76d8-f8a0-4f53-bc93-f2777576b7b9` | [`misp-galaxy-cluster/…`](misp-galaxy-cluster/extension-definition--573a76d8-f8a0-4f53-bc93-f2777576b7b9.json) |
| MISP Property Extension | `property-extension` | `extension-definition--5ece67ea-2e8b-4ed0-bb69-26d69053ee0b` | [first file](extension-definition--5ece67ea-2e8b-4ed0-bb69-26d69053ee0b.json), [body](misp-property-extension.json) |

The three `new-sdo` extensions each define one object type, `misp-attribute`, `misp-object` and
`misp-galaxy-cluster`. The property extension is one extension shared by every standard STIX
object type MISP extends: SDOs such as `attack-pattern`, `location`, `malware` or
`threat-actor`, SCOs such as `file`, `url` or `windows-registry-key`, and `indicator`, `note` and
`opinion`.

The four extension definitions are created by the MISP Project:

```json
{
    "type": "identity",
    "spec_version": "2.1",
    "id": "identity--55f6ea65-aa10-4c5a-bf01-4f84950d210f",
    "created": "2015-09-14T15:40:21.000Z",
    "modified": "2015-09-14T15:40:21.000Z",
    "name": "MISP",
    "identity_class": "organization"
}
```

Each extension definition has a **version** of its own, following semantic versioning, raised
when its schema changes. This document describes version 1.0.0 of all four. The extension
definition objects, and this identity, are packaged with the MISP-STIX converter, in
[`misp_stix_converter/data/misp_extensions/`](https://github.com/MISP/misp-stix/tree/main/misp_stix_converter/data/misp_extensions).

The MISP labels (`misp:type="…"`, `misp:category="…"`, `misp:name="…"`, `misp:galaxy-name="…"`,
…) are standard **labels**, and are not part of the MISP Extensions.

### 1.3 Directory Layout

| Path | Content |
| -- | -- |
| `extension-definition--5ece67ea-2e8b-4ed0-bb69-26d69053ee0b.json` | The property extension's first schema file |
| `misp-property-extension.json` | The property extension's body |
| `misp-attribute/`, `misp-object/`, `misp-galaxy-cluster/` | The schema of each `new-sdo` type |
| `examples/` | Bundles using the extensions ([section 8](#8-examples)) |
| `README.md` | This document |

The first schema file of each extension is named after its extension definition id, so the STIX
validator finds them all when given this directory: `stix2_validator --schemas <this directory>`. The schemas refer
to the STIX 2.1 base schemas (`core.json`, `timestamp.json`, `binary.json`) by their published
URLs.

## 2. MISP Property Extension

**Extension definition id:** `extension-definition--5ece67ea-2e8b-4ed0-bb69-26d69053ee0b`

**Extension type:** `property-extension`

The MISP Property Extension holds the MISP values a standard STIX object has no property for:

- on an object coming from a MISP object, the values of the object relations its standard
  properties leave over;
- on an object coming from a galaxy cluster, the cluster meta values its standard properties
  leave over;
- a few MISP fields with a name of their own ([section 2.1](#21-properties));
- the values of the MISP objects nested in a STIX structure, in the **Nested Rooms**
  ([section 2.5](#25-nested-rooms)).

An object comes either from a MISP object or from a galaxy cluster, so object relations and meta
keys never meet on one object. The MISP-STIX converter writes the extension only on an object
holding at least one MISP value, next to the object's predefined extensions
(`windows-pebinary-ext`, `socket-ext`, …):

```json
"extensions": {
    "windows-pebinary-ext": {"pe_type": "exe", "sections": [{"name": ".rsrc"}, {"name": ".text"}]},
    "extension-definition--5ece67ea-2e8b-4ed0-bb69-26d69053ee0b": {
        "extension_type": "property-extension",
        "entropy": "1.234",
        "windows_pebinary_ext": {
            "lang_id": "080904B0",
            "sections": {"1": {"text": "Code section"}}
        }
    }
}
```

### 2.1 Properties

| Property Name | Type | Description |
| -- | -- | -- |
| **extension_type** (required) | `string` | The value of this property **MUST** be `property-extension`. |
| **opinion** (optional) | `integer` | On an `opinion`: the MISP analyst opinion, from 0 to 100, which the STIX **opinion** property rounds to its enumeration. |
| **author_ref** (optional) | `identifier` | On the `opinion` standing for a MISP false positive sighting: the identity of the organisation reporting it. The value **MUST** be an `identity` identifier. |
| **attachment** (optional) | *value* | The values of MISP `attachment` attributes no standard property holds, each with its data where it has some. |
| **filename** (optional) | *value* | On an `artifact`: the name of the file whose content **payload_bin** holds, a MISP attachment or malware sample. The MISP-STIX converter writes one `string`. |
| **url** (optional) | *value* | On an `artifact` holding an image: the image URL, which STIX 2.1 does not allow next to **payload_bin**. The MISP-STIX converter writes one `string`. |
| **malware_sample** (optional) | *value* | The value of a MISP `malware-sample` attribute, `<file name>\|<MD5>`, kept whole where no standard property holds it. The MISP-STIX converter writes one `string`. |
| **original_names** (optional) | `dictionary` | The spellings of the galaxy cluster meta keys the naming changed ([section 2.4](#24-original-names)). |
| **windows_pebinary_ext** (optional) | `dictionary` | The Nested Room of the `windows-pebinary-ext` extension ([section 2.5](#25-nested-rooms)). |
| **values** (optional) | `dictionary` | The Nested Room of the **values** of a `windows-registry-key` ([section 2.5](#25-nested-rooms)). |
| any other name | *value* | The values of one MISP object relation or galaxy cluster meta key, under its Extension Property Name ([section 2.2](#22-extension-property-names)). |

The names in this table are the fixed names of the extension. Any other name **MUST** match
`^[a-z][a-z0-9_]{2,249}$`. Each level of the extension is closed: a property not listed here and
not matching the pattern is invalid.

### 2.2 Extension Property Names

A MISP object relation or galaxy cluster meta key is written under its Extension Property Name:

1. The relation or key is lowercased, and every character outside `a`-`z`, `0`-`9` and `_` is
   turned into `_`: `KnownMalicious` gives `knownmalicious`, `cfr-type-of-incident` gives
   `cfr_type_of_incident`.
2. The result is escaped where it cannot be used as it is:
   - shorter than three characters, not starting with a letter, or one of the names the
     extension uses for itself (`extension_type`, `original_names`, `windows_pebinary_ext`,
     `sections`, `values`): it takes the prefix `misp_`. `ip` gives `misp_ip`, `2fa-device-ip`
     gives `misp_2fa_device_ip`;
   - ending with `_hex` or `_bin`, which the STIX 2.1 base schema types as hexadecimal and
     binary: it takes a trailing `_`. `origin:Temp.Hex` gives `origin_temp_hex_`;
   - when both apply, the prefix comes first, then the trailing `_`.

The six MISP fields of [section 2.1](#21-properties), **opinion**, **author_ref**,
**attachment**, **filename**, **url** and **malware_sample**, keep their names, with no fold and
no escape: a relation folding to one of them is that MISP field. A relation folding to
**extension_type**, **original_names**, **windows_pebinary_ext**, **sections** or **values** is
escaped.

A consumer reads a name back by removing its escape: a trailing `_` after `_hex` or `_bin`, then
a `misp_` prefix when the rest would itself be escaped (`misp_ip` gives `ip`, `misp_uuid` stays).
The MISP-STIX import then restores the spelling of an object relation from the MISP object
template named by the object's `misp:name` label, and the spelling of a meta key from
**original_names**.

When two values of one object land on one name, the last one is kept, and the MISP-STIX converter
reports the other one lost.

### 2.3 Values

A *value* is one item, or a `list` of at least two items:

- one value is written as the item itself, two or more as a list;
- an item is a `string`, a `boolean`, or a `dictionary` with exactly two properties, **value**
  (`string`) and **data** (`binary`), for a MISP attribute carrying a payload;
- a list **MAY** mix items with and without **data**.

Galaxy cluster meta values are strings. MISP holds every meta value as a list: a meta key with one
value is written as a `string`, and a meta key with no value is not written.

### 2.4 Original Names

**original_names** maps the Extension Property Name of a galaxy cluster meta key to the key as
MISP spells it, for every meta key the naming of [section 2.2](#22-extension-property-names)
changed:

```json
"extension-definition--5ece67ea-2e8b-4ed0-bb69-26d69053ee0b": {
    "extension_type": "property-extension",
    "capital": "Stockholm",
    "iso3": "SWE",
    "tld": ".se",
    "original_names": {"capital": "Capital", "iso3": "ISO3"}
}
```

- It is written only when the naming changed at least one meta key of the object, and then lists
  every name it changed: a meta key it does not list is spelled as its name (`tld` above).
- It **MUST** hold at least one entry, and each key **MUST** match `^[a-z][a-z0-9_]{2,249}$`.
- An entry naming no property of the object is ignored.
- Object relations get no entry: the MISP object template gives their spelling back.

### 2.5 Nested Rooms

STIX 2.1 defines **extensions** at the top level of an object only (STIX 2.1, section 3.2), and
gives no custom key a place inside a predefined extension, a PE section or a registry value. A
MISP object nested in such a STIX structure keeps its values in a room of the property extension
that mirrors that structure:

| Room | On | Holds the values of | Mirrors |
| -- | -- | -- | -- |
| **windows_pebinary_ext** | `file` | the MISP `pe` object | the `windows-pebinary-ext` extension |
| **windows_pebinary_ext**.**sections** | `file` | the MISP `pe-section` objects | its **sections** |
| **values** | `windows-registry-key` | the MISP `registry-key-value` objects | its **values** |

- A room holds Extension Property Names and *values*, as the top level does.
  **windows_pebinary_ext** holds **sections**; nothing else holds a room.
- A room standing for a STIX list (**sections**, **values**) is a `dictionary` keyed by the
  zero-based position of the STIX list's items, in decimal: its key `"n"` holds the values of the
  MISP object that the STIX list's item `n` stands for. Each key **MUST** match
  `^(0|[1-9][0-9]*)$`, so that a position has one spelling, and name an item of the STIX list.
- A list room holds only the items with values, its keys in ascending order: an item holding none
  has no key, and **MUST NOT** be written as `{}`. A list room with no item is left out: it
  **MUST** hold at least one key. **windows_pebinary_ext** is left out when nothing is left in it:
  it **MUST NOT** be empty.
- A MISP `registry-key-value` holding only values STIX has no property for keeps its item in the
  key's **values**, as `{}`, so that its position holds
  ([section 7.4](#74-an-empty-registry-value)):

  ```json
  "values": [{"name": "Foo", "data": "qwerty", "data_type": "REG_SZ"}, {}],
  "extensions": {
      "extension-definition--5ece67ea-2e8b-4ed0-bb69-26d69053ee0b": {
          "extension_type": "property-extension",
          "values": {"1": {"benign": "Known to be legitimate"}}
      }
  }
  ```

- The values of the MISP `registry-key` object itself stay at the top level of the extension. So
  does a second **data** value of that object.

### 2.6 Patterns

On a standard object, an Indicator's pattern is the only place a MISP value's `to_ids` flag, its
detection-ready mark, travels. An Indicator compares a MISP value where the observable holds it,
through the object path of the property extension (STIX 2.1, section 9.7):

| Where the observable holds the value | Object path |
| -- | -- |
| In the property extension | `url:extensions.'extension-definition--5ece67ea-2e8b-4ed0-bb69-26d69053ee0b'.misp_ip` |
| Behind a reference | `file:content_ref.extensions.'extension-definition--5ece67ea-2e8b-4ed0-bb69-26d69053ee0b'.filename` |
| In **windows_pebinary_ext** | `file:extensions.'extension-definition--5ece67ea-2e8b-4ed0-bb69-26d69053ee0b'.windows_pebinary_ext.lang_id` |
| In **sections** | `file:extensions.'extension-definition--5ece67ea-2e8b-4ed0-bb69-26d69053ee0b'.windows_pebinary_ext.sections.'1'.text` |
| In **values** | `windows-registry-key:extensions.'extension-definition--5ece67ea-2e8b-4ed0-bb69-26d69053ee0b'.values.'0'.benign` |

- The extension definition id and the room keys are quoted, a room key since it starts with a
  digit; the names are not.
- A value the room item holds in a list keeps its `[*]` behind the key:
  `….sections.'1'.text[*] = 'a'`.
- A value the observable holds in a list is compared through `[*]`: a relation holding `a`, `b`
  and `c`, of which `a` and `c` are flagged, gives `….text[*] = 'a' AND ….text[*] = 'c'`.
- A value with data is compared twice, on its **data**, then on its **value**:
  `….user_avatar.data = '…' AND ….user_avatar.value = 'avatar.png'`. Under `[*]`, the two
  comparisons **MAY** match two different items of the list.
- The process parent's values are compared behind `parent_ref`, under the name of the relation
  with its `parent-` removed: `process:parent_ref.extensions.'…'.process_name`.
- A comparison on a property of the extension matches only an observation carrying the extension.

## 3. MISP Attribute Extension

**Type Name:** `misp-attribute`

**Extension definition id:** `extension-definition--c1f2c0fa-3786-4f27-bf57-cf050ecfc104`

**Extension type:** `new-sdo`

A MISP attribute no standard STIX object represents: an attribute type the converter maps to no
STIX object (`btc`, `iban`, …), an attribute not flagged for detection that holds too little for
an observable (`port`, `size-in-bytes`, …), or a `malware-sample` whose MD5 is not valid. Its **id** carries the uuid of the MISP attribute.

### 3.1 Properties

| | |
| -- | -- |
| **Required Common Properties** | **type**, **spec_version**, **id**, **created**, **modified**, **extensions** |
| **Optional Common Properties** | **created_by_ref**, **revoked**, **labels**, **confidence**, **lang**, **external_references**, **object_marking_refs**, **granular_markings** |
| **MISP Attribute Specific Properties** | **attribute_type**, **value**, **category**, **comment**, **to_ids**, **first_seen**, **last_seen**, **data** |

| Property Name | Type | Description |
| -- | -- | -- |
| **type** (required) | `string` | The value of this property **MUST** be `misp-attribute`. |
| **extensions** (required) | `dictionary` | **MUST** hold `extension-definition--c1f2c0fa-3786-4f27-bf57-cf050ecfc104`, whose value is `{"extension_type": "new-sdo"}`. |
| **attribute_type** (required) | `string` | The MISP attribute type, such as `btc`. Named so since **type** is the STIX type. |
| **value** (required) | `string` | The attribute value. |
| **category** (required) | `string` | The MISP category, such as `Financial fraud`. |
| **comment** (optional) | `string` | The attribute comment. |
| **to_ids** (required) | `boolean` | Whether the attribute is flagged for detection. |
| **first_seen** (optional) | `timestamp` | When the attribute was first seen. |
| **last_seen** (optional) | `timestamp` | When the attribute was last seen. |
| **data** (optional) | `binary` | The payload of an attribute carrying one, such as an attachment or a malware sample. |

## 4. MISP Object Extension

**Type Name:** `misp-object`

**Extension definition id:** `extension-definition--a093107b-933f-4d72-a9a6-6d7318adadda`

**Extension type:** `new-sdo`

A MISP object no standard STIX object represents, with its attributes: an object template the
converter maps to no STIX object (`bank-account`, `btc-wallet`, …), or an object its STIX mapping
cannot take. Its **id** carries the uuid of the MISP object.

### 4.1 Properties

| | |
| -- | -- |
| **Required Common Properties** | **type**, **spec_version**, **id**, **created**, **modified**, **extensions** |
| **Optional Common Properties** | **created_by_ref**, **revoked**, **labels**, **confidence**, **lang**, **external_references**, **object_marking_refs**, **granular_markings** |
| **MISP Object Specific Properties** | **name**, **meta_category**, **comment**, **attributes**, **first_seen**, **last_seen** |

| Property Name | Type | Description |
| -- | -- | -- |
| **type** (required) | `string` | The value of this property **MUST** be `misp-object`. |
| **extensions** (required) | `dictionary` | **MUST** hold `extension-definition--a093107b-933f-4d72-a9a6-6d7318adadda`, whose value is `{"extension_type": "new-sdo"}`. |
| **name** (required) | `string` | The name of the MISP object template. |
| **meta_category** (required) | `string` | The MISP object meta category. |
| **comment** (optional) | `string` | The object comment. |
| **attributes** (required) | `list` of MISP object attribute | The object attributes ([section 4.2](#42-misp-object-attribute)). The list **MUST** hold at least one. |
| **first_seen** (optional) | `timestamp` | When the object was first seen. |
| **last_seen** (optional) | `timestamp` | When the object was last seen. |

### 4.2 MISP Object Attribute

An item of **attributes** keeps the keys MISP gives an object attribute. It is a `dictionary` in a
list, so its **type** names the MISP attribute type and clashes with nothing.

| Property Name | Type | Description |
| -- | -- | -- |
| **type** (required) | `string` | The MISP attribute type. |
| **object_relation** (required) | `string` | The object relation, as MISP spells it, with any `(s)` removed. |
| **value** (required) | `string` | The attribute value. |
| **category** (optional) | `string` | The MISP category. |
| **comment** (optional) | `string` | The attribute comment. |
| **to_ids** (required) | `boolean` | Whether the attribute is flagged for detection. |
| **uuid** (optional) | `string` | The uuid of the MISP attribute. |
| **data** (optional) | `binary` | The payload of an attribute carrying one. |
| **first_seen** (optional) | `timestamp` | When the attribute was first seen. |
| **last_seen** (optional) | `timestamp` | When the attribute was last seen. |

## 5. MISP Galaxy Cluster Extension

**Type Name:** `misp-galaxy-cluster`

**Extension definition id:** `extension-definition--573a76d8-f8a0-4f53-bc93-f2777576b7b9`

**Extension type:** `new-sdo`

A MISP galaxy cluster no standard STIX object represents: a cluster of a galaxy the converter maps
to no STIX object type. Its **id** carries the uuid of the cluster. **created** and **modified**
take the timestamp of the event, attribute or object the cluster is attached to, else the
cluster's own, else the export time. The MISP-STIX converter
writes no **created_by_ref**: a cluster is not authored by the organisation exporting it.

### 5.1 Properties

| | |
| -- | -- |
| **Required Common Properties** | **type**, **spec_version**, **id**, **created**, **modified**, **extensions** |
| **Optional Common Properties** | **created_by_ref**, **revoked**, **labels**, **confidence**, **lang**, **external_references**, **object_marking_refs**, **granular_markings** |
| **MISP Galaxy Cluster Specific Properties** | **galaxy_name**, **galaxy_type**, **galaxy_description**, **value**, **description**, **meta**, **original_names** |

| Property Name | Type | Description |
| -- | -- | -- |
| **type** (required) | `string` | The value of this property **MUST** be `misp-galaxy-cluster`. |
| **extensions** (required) | `dictionary` | **MUST** hold `extension-definition--573a76d8-f8a0-4f53-bc93-f2777576b7b9`, whose value is `{"extension_type": "new-sdo"}`. |
| **galaxy_name** (required) | `string` | The name of the galaxy. |
| **galaxy_type** (required) | `string` | The type of the galaxy. |
| **galaxy_description** (optional) | `string` | The description of the galaxy. |
| **value** (required) | `string` | The cluster value. |
| **description** (optional) | `string` | The cluster's own description. |
| **meta** (optional) | `dictionary` | The cluster meta: each key holds a `string`, or a `list` of at least two strings ([section 2.3](#23-values)). The keys are the MISP meta keys with every character outside `a`-`z`, `A`-`Z`, `0`-`9`, `_` and `-` turned into `_` (STIX 2.1, section 2.3). |
| **original_names** (optional) | `dictionary` | Maps each **meta** key that differs from the MISP meta key to the key as MISP spells it. Written only when at least one key differs. |

## 6. Bundles

A bundle the MISP-STIX converter writes carries the extension definitions its objects use, and
the MISP Project identity creating them, each once:

- An extension definition is used when an object of the bundle names its id: a `misp-*` object,
  a key of an object's **extensions**, or an object path in an Indicator's pattern.
- In an event, the identity and the extension definitions go after the identity of the event's
  organisation, ahead of the Report or Grouping of the first event using them:
  `[organisation identity, MISP Project identity, extension definitions…, report, objects…]`.
- In an attribute or object collection, which has no Report, they go ahead of the first object
  using them.
- The **object_refs** of a Report or Grouping do not list them.
- A bundle with no MISP Extension content carries neither the identity nor any extension
  definition.

The order of a bundle has no meaning in STIX. A consumer **SHOULD NOT** rely on it, nor on the
extension definitions being present: the extension definition ids of this document are fixed.

## 7. Conformance Notes

### 7.1 The Property Extension's First Schema File Refers to No Base Type

The STIX Extension Definition Policy (Appendix A.1, item 6) asks the first schema file of a
property extension to start with an `allOf` whose first part refers to the base schema of the
object type it extends. The MISP Property Extension extends about 25 object types and cannot
refer to one of them: its first schema file only requires **extensions** to hold the extension
definition id, with the body schema as its value. The STIX 2.1 base schemas of the object types
check the rest of each object.

### 7.2 The Schema Does Not Tie a Nested Room to Its Type

The body schema accepts **windows_pebinary_ext** and **values** on any object type. The MISP-STIX
converter writes **windows_pebinary_ext** on a `file` only, and **values** on a
`windows-registry-key` only. The MISP-STIX import refuses an object whose room has a key naming no
item of its STIX list, or no extension to stand for.

### 7.3 No External References

The STIX Extension Definition Policy (sections 3.3 and 3.4) asks an extension definition to
reference its documentation and examples through **external_references**. The MISP Extensions
carry none: the **schema** URL already points into this directory, which holds both.

### 7.4 An Empty Registry Value

A MISP `registry-key-value` holding only values STIX has no property for is written as `{}` in
the **values** of its `windows-registry-key`, so that its position, the key of its room in the
property extension, holds ([section 2.5](#25-nested-rooms)). STIX 2.1 (section 6.17.2) requires a
registry value to hold at least one property, so such an item breaks the STIX 2.1 base schema.

## 8. Examples

The files of [`examples/`](examples/) are bundles the MISP-STIX converter exported from its own
test events, and validate against the schemas of this directory. Two of those test events were
changed before the export, the way the converter's tests change them, to show a case no test
event holds as it is: a section with no MISP value, and values with data held in a list.

| File | Shows |
| -- | -- |
| [`misp-attribute.json`](examples/misp-attribute.json) | `misp-attribute` objects: two attribute types no STIX object represents, and four not flagged for detection that hold too little for an observable. |
| [`misp-object.json`](examples/misp-object.json) | `misp-object` objects, with **first_seen** and **last_seen** on the object and on attributes, and an attachment with its **data**. |
| [`misp-galaxy-cluster.json`](examples/misp-galaxy-cluster.json) | A `misp-galaxy-cluster`, with a **meta** key whose spelling **original_names** keeps. |
| [`location-with-galaxy-meta.json`](examples/location-with-galaxy-meta.json) | The property extension on two `location` SDOs from galaxy clusters: meta values as a `string` and as a `list`, and **original_names**. |
| [`url-with-misp-values.json`](examples/url-with-misp-values.json) | The property extension on a `url` SCO: object relation values, among which the escaped `misp_ip`, and the Indicator comparing them. |
| [`file-with-pe-rooms.json`](examples/file-with-pe-rooms.json) | A `file` with the **windows_pebinary_ext** and **sections** rooms: the first section holds no MISP value and has no key. |
| [`windows-registry-key-with-values-room.json`](examples/windows-registry-key-with-values-room.json) | A `windows-registry-key` with the **values** room. |
| [`indicator-comparing-values-with-data.json`](examples/indicator-comparing-values-with-data.json) | An Indicator comparing values with data held in a list: `[*]`, with **data** then **value**. |

## Appendix A. The Custom Syntax

*This appendix is informative.*

Up to misp-stix version 2026.10.12, the STIX 2.1 export carried the same content as custom STIX objects
and properties (STIX 2.1, section 11), which the STIX 2.0 export still writes:

- `x-misp-attribute`, `x-misp-object` and `x-misp-galaxy-cluster` objects, where the MISP
  Extensions write `misp-attribute`, `misp-object` and `misp-galaxy-cluster`, with the same uuid
  in their ids;
- `x_misp_*` properties at the top level of standard objects, where the property extension
  holds the same values under their Extension Property Names, and **x_misp_original_names**,
  where it holds **original_names**;
- MISP values inside `windows-pebinary-ext`, its sections and registry values, where the Nested
  Rooms hold them.

The MISP-STIX import reads both forms, object by object, and gives the same MISP content.
