# MISP-STIX-Converter - Mapping documentation

This documentation describes how the conversion between MISP and STIX works in terms of mapping both formats together (as opposed to [the more generic description of the library itself](https://github.com/chrisr3d/MISP-STIX-Converter/blob/main/README.md), describing how to use it).  
Thus, it gives a detailed description of the inputs and outputs that are to expect depending on the type of data to convert.

## Summary

* [Introduction](#Introduction)
* [MISP to STIX](#MISP-to-STIX)
    * [MISP to STIX1](#MISP-to-STIX1)
        * [Events to STIX1](#Events-to-STIX1-mapping)
        * [Attributes to STIX1](#Attributes-to-STIX1-mapping)
        * [Objects to STIX1](#Objects-to-STIX1-mapping)
        * [Galaxies to STIX1](#Galaxies-to-STIX1-mapping)
    * [MISP to STIX 2.0](#MISP-to-STIX-20)
        * [Events to STIX 2.0](#Events-to-STIX-20-mapping)
        * [Attributes to STIX 2.0](#Attributes-to-STIX-20-mapping)
        * [Objects to STIX 2.0](#Objects-to-STIX-20-mapping)
        * [Galaxies to STIX 2.0](#Galaxies-to-STIX-20-mapping)
    * [MISP to STIX 2.1](#MISP-to-STIX-21)
        * [Events to STIX 2.1](#Events-to-STIX-21-mapping)
        * [Attributes to STIX 2.1](#Attributes-to-STIX-21-mapping)
        * [Objects to STIX 2.1](#Objects-to-STIX-21-mapping)
        * [Galaxies to STIX 2.1](#Galaxies-to-STIX-21-mapping)
* [Future improvements](#Future-Improvements)

## Introduction

MISP supports 2 majors features regarding STIX:
- The export of data collections from MISP to STIX
- The import of STIX content into a MISP Event

More specifically, MISP can generate **STIX1.1** and **STIX2.0** content from a given event using the UI (`Download as...` feature available in the event view), or any collection of event(s) using the built-in restSearch client.  
In order to do so, MISP gives data formatted in the standard misp format (used in every communication between connected MISP instances for example) to the corresponding export script (available within the [STIX export directory](https://github.com/chrisr3d/MISP-STIX-Converter/blob/main/misp_stix_converter/stix_export) of this repository) which returns STIX format.

It is also possible to import STIX data into MISP using again either the UI interface or the restSearch client (should support versions 1.1, 1.2, 2.0 and 2.1). In this case everything imported is put into a single MISP Event.  
In order to use that functionality, users can either pass the content of their STIX file to the restSearch client, or upload it using the `Import from...` feature available in the events list view. In both cases, the content of the file is then passed to the corresponding import script (available within the [STIX import directory](https://github.com/chrisr3d/MISP-STIX-Converter/blob/main/misp_stix_converter/stix_import) of this repository) which returns MISP format that is going to be saved as an Event in MISP.

Within this documentation we focus on the mapping between MISP and STIX formats.
