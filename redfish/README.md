# DMTF Redfish HPE iLO - Postman Collections

## Introduction

These collections template the HPE iLO Redfish APIs to aid prototyping and reduce the learning curve for wokring with Redfish.

They consist of collections for Postman by Postdot Technologies, Inc., they are provided "as-is" under the terms of the accompanying license (LICENSE.md).

Note: iLO is a product of Hewlett Packard Enterprise Development LP, these collections are provided for convenience and not in any way associated with HPE.

#### Versions
| Release   | Release Date      | Notes             | Bugs Fixed    |
|-----------|-------------------|-------------------|---------------|
| 0.1 			| 2020/06/16				|Initial draft for iLO 4  | |

#### Authors & Contributors
| Name                 | Organization      | Contact                                                          |
|----------------------|-------------------|------------------------------------------------------------------|
| Scott Donaldson      | Vertiv            | scott.donaldson@vertiv.com                |

## Support

These collections are provided to aid Vertiv Software Delivery, Services and
Software Delivery, Support teams, guidance and support for Postman - or
alternatives - is not provided.

| Release   | Support Status      | Notes             | Postman Compatibility    | iLO Compatibility | iLO Validated |
|-----------|-------------------|-------------------|---------------|----------------------|--------|
| 0.1 			| Supported | | Collection v2.1 | iLO 4 v2.30+ | iLO 4 v2.73 |

#### Maintainers

Feedback on function, errata and enhancements is welcome, this can be sent to the following mailbox.


| Name                 | Organization      | Contact                                                          |
|----------------------|-------------------|------------------------------------------------------------------|
| Professional Services     | Vertiv            | global.services.delivery.development@vertiv.com                |

### License

Re-distribution is subject to the terms of the included license (LICENSE.MD) and/or any terms of third-party distribution*.
* Pending Postman API Network inclusion.

## Instructions

### Getting Started

To use these templates, it is necessary to create appropriate environments
within Postman, these must include the following variable definitions.

| Variable | Usage | Values / Example | Required? |
|----------|-------|--------|-----------|
| `username` | Trellis account name. | `Administrator` | Yes |
| `password` | Trellis account password. | `Example!Pass#2020` (Example) | Yes |
|	`proto` | Transport protocol to use. | `http`\|`https` | Yes |
|	`host` | Trellis front server name. | `trellis.example.org` (Example) | Yes |
|	`port` | Port number to utilize. | `443`\|`6443` | Yes |
| `content-type` | Content-Type to utilize for body and expected type for response. | `application/json` | Yes |
| `x-auth-token` | Session token generated from authenticating. | `988622bacf4ec71f0cea5c48efef34d6` (Example) | Yes |
| `session_id` | Session identifier generated from authenticating. | `user6ae8ee47636cbabe` (Example) | No |

**Configuration Steps**
1. Select "Manage Environments" from top right of interface.
2. Press "Add" to create a new environment definition.
3. Set environment name in top menu.
4. Add all five variables as defined above with appropriate values.
5. Save the new environment by pressing "Add".
6. Close environments menu.
7. Select environment from environment drop down menu in top right corner.

## Resources
### HPE Support
* HPE iLO 4 [Firmware Downloads](https://support.hpe.com/hpesc/public/km/product/1009143853/Product#t=All&sort=relevancy&numberOfResults=25)
* HPE iLO 5 [Firmware Downloads](https://support.hpe.com/hpesc/public/km/product/1010145741/hpe-integrated-lights-out-5--ilo-5--firmware-for-hpe-gen10-servers?ismnp=0&l5oid=1010145467#t=DriversandSoftware&sort=relevancy&layout=table&numberOfResults=25&f:@kmswsoftwaretypekey=[swt8000029]&hpe=1)

### Postman

* Postman can be downloaded from [Postman](https://www.getpostman.com/apps).
* Postman Interceptor can be downloaded for [Google Chrome](https://chrome.google.com/webstore/detail/postman-interceptor/aicmkgpgakddgnaphhhpliifpcfhicfo/)
