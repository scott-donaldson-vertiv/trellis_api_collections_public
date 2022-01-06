# Trellis™ Enterprise - Collections

## Introduction

These collections are templates for Postman by Postdot Technologies, Inc., they are
provided "as-is" under the terms of the accompanying license (LICENSE.txt).

#### Versions
| Release   | Release Date      | Notes             | Bugs Fixed    |
|-----------|-------------------|-------------------|---------------|
| 0.7.1		| 2021/06/03		| Added Python 3 examples. Corrected license details and year. | |
| 0.6		| 2020/07/08		| Additional monitoring API calls added including monitoring examples. | |
| 0.4		| 2020/06/26		| Additions of JSON schema definitions for 5.1.1.12 (GA) release. | |
| 0.3 		| 2020/06/16		| Additions for Trellis 5.1.x, additional fields for {{content-type}} and tests to validate response type matches requested type.  | |
| 0.2		| 2018/09/27		| Corrections for managed environment variables for {{password}}. | |
| 0.1		| 2018/01/31        | Updated collection for 5.0.x, updated 4.0.x to use new managed environment variables for improved flexibility. | |

#### Authors & Contributors
| Name                 | Organization      | Contact                                                          |
|----------------------|-------------------|------------------------------------------------------------------|
| Scott Donaldson      | Vertiv Infrastructure Ltd.           | scott.donaldson@vertiv.com                |
| Michael B Jones      | Vertiv Group Corp.           | michael.b.jones@vertiv.com                |
| Mark Zagorski      | Vertiv Infrastructure Ltd.           | mark.zagorski@vertiv.com                |

## Support

These collections are provided to aid Vertiv Software Delivery, Services and
Software Delivery, Support teams, guidance and support for Postman - or
alternatives - is not provided.

| Release   | Support Status      | Notes             | Postman Compatibility    | Trellis Compatibility |
|-----------|-------------------|-------------------|---------------|----------------------|
| 0.5 			| Supported | | Collection v2.1 | 5.1.x, 5.0.x, 4.0.x* |
| 0.4 			| Supported | | Collection v2.1 | 5.1.x, 5.0.x, 4.0.x* |
| 0.3 			| Supported | | Collection v2.1 | 5.1.x, 5.0.x, 4.0.x* |
| 0.2				| Deprecated. | | Collection v2 | 5.0.x, 4.0.x |
| 0.1			  | Unsupported. | | Collection v1 | 5.0.x, 4.0.x |

#### Maintainers

Feedback on function, errata and enhancements is welcome, this can be sent to the
following mailbox.

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

| Variable | Usage | Values | Required? |
|----------|-------|--------|-----------|
| username | Trellis account name. | `TrellisAdministrator` | Yes |
| password | Trellis account password. | `Example!Pass#2020` | Yes |
|	proto | Transport protocol to use. | `http`\|`https` | Yes |
|	host | Trellis front server name. | `trellis.example.org` | Yes |
|	port | Port number to utilize. | `443`\|`6443` | Yes |
| content-type | Content-Type to utilize for body and expected type for response. | `application/json` | Yes |
| query-limit-ms | Response limit time for SLA. | `query-limit-ms` | Yes |

**Configuration Steps**
1. Select "Manage Environments" from top right of interface.
2. Press "Add" to create a new environment definition.
3. Set environment name in top menu.
4. Add all five variables as defined above with appropriate values.
5. Save the new environment by pressing "Add".
6. Close environments menu.
7. Select environment from environment drop down menu in top right corner.

## Resources

### Postman

* Postman can be downloaded from [Postman](https://www.getpostman.com/apps).
* Postman Interceptor can be downloaded for [Google Chrome](https://chrome.google.com/webstore/detail/postman-interceptor/aicmkgpgakddgnaphhhpliifpcfhicfo/)
