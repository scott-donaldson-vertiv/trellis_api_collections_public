# ---------------------------------------------------------------------------------------------
# Title:		    Trellis(tm) Enterprise - Top of Rack Search
# Description:      Returns racks with their modules and port types based on top of rack and
#                   location criteria.
# Script Name:      te_tor_search.py
# Created:          2021/04/27
# Modified:         2021/06/03
# Author:           Scott Donaldson [VERTIV/AVOCENT/UK]
# Contributors:
# Company:          Vertiv Infrastructure Ltd.
# Group:            Life-Cycle Engineering, IT Systems
# Email:            global.services.delivery.development@vertivco.com
# License:          BSD-3 Clause (included)
# Instructions:     README.md
# ---------------------------------------------------------------------------------------------

import argparse
import getpass
import json
import logging.config
import os
import sys
from datetime import datetime
from http import HTTPStatus
from natsort import natsorted
from time import process_time, perf_counter, sleep, time_ns, time, strftime
from collections import OrderedDict

import urllib3
from backoff import on_exception, expo
from ratelimit import limits, RateLimitException
from requests import Request, Session, Response
from urllib3 import PoolManager, HTTPResponse
from urllib3.exceptions import InsecureRequestWarning, SSLError, MaxRetryError

urllib3.disable_warnings(InsecureRequestWarning)

"""
Configuration Defaults

CAUTION: It is strongly encouraged to pass values via launch arguments (except password which is discouraged)
"""
DEFAULT_TRELLIS_HOST = 'trellis-front'
DEFAULT_TRELLIS_USER = 'TrellisAdministrator'
DEFAULT_TRELLIS_PASS = 'Passw0rd'
DEFAULT_CONN_PROTO = 'https'
DEFAULT_CONN_PORT = 443
DEFAULT_TIMESERIES_FORMAT = '%Y-%m-%dT%H:%M:%S.%f+0000'
DEFAULT_API_ROOT = '/api/rest/v1/'
DEFAULT_RATE_WINDOW = 60
DEFAULT_RATE_LIMIT = 10000
DEFAULT_REQUEST_HEADERS = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-cache',
    'Accept-Charset': 'utf-8',
    'Accept': 'application/json; application/hal+json'
}
DEFAULT_MATCH_NAME = '_test'
DEFAULT_MATCH_OWNER = 'vertiv'
DEFAULT_MATCH_DAYS = 1
def_proc = None

DEFAULT_DEBUG_VERBOSITY = 2  # 1: Normal debug output, 2: Adds raw payload output.

"""
API Paths
"""
PATH_BUILDINGS = 'buildings/'
PATH_BUILDINGS_SEARCH_FBQ = 'buildings/search/findByQuery'
PATH_BUILDINGS_SEARCH_FBNIC = 'buildings/search/findByNameIsContaining'

PATH_DATA_POINT_DEFS = 'datapointdefinitions/search/findDatapointDefinitionsByDevice'
PATH_DATA_POINTS = 'datapoints/search/getTimeseriesData'

PATH_DEVICES = 'devices/'
# PATH_DEVICES_SEARCH_FBNICAOCPNIC = 'devices/search/findByObjectCategoryProgrammaticName'
PATH_DEVICES_SEARCH_FBNICAOCPNIC = 'devices/search/findByNameIsContainingAndObjectCategoryProgrammaticNameIsContaining'
PATH_DEVICES_SEARCH_FBQ = 'devices/search/findByQuery'

PATH_FLOORS = 'floors/'
PATH_FLOORS_SEARCH_FBNIC = 'floors/search/findByNameIsContaining'

PATH_SPACES_SEARCH_FBNIC = 'spaces/search/findByNameIsContaining'

PATH_ZONES_SEARCH_FBNIC = 'zones/search/findByNameIsContaining'

'''
API Limits
TODO: Replace these with input values.
'''
SENSORS_PAGE_SIZE = 1000
METRICS_PAGE_SIZE = 1000
BUILDINGS_PAGE_SIZE = 1000

'''
Sanitization Constraints
'''
SANITIZE_MAX_STRING = 255
SANITIZE_MAX_URL = 2000  # While RFC 2616 is unbounded, safe limit is generally considered 2000 (2083 for IE).
SANITIZE_MAX_HOSTNAME = 250  # RFC 1035 assuming single . and null with label.
SANITIZE_MAX_HOSTNAME_LABEL = 63
SANITIZE_MAX_PAGE_SIZE = 1000  # Trellis 4.0.3+ constrains results per page to 1000
SANITIZE_RESULT_LIMIT = 100


class TestCriteria:
    _owner: str = None  # "OWNER"
    _match: str = None  # "SNMP_TEST", "BACnet_TEST", "Modbus_TEST"

    def __init__(self, owner: str = "", match: str = "TEST"):
        if 1 > len(owner) <= SANITIZE_MAX_STRING:
            # TODO: Safely escape unsupported characters
            self._owner = owner
        else:
            assert ValueError, "Owner criteria out of range."

        if 1 > len(match) <= SANITIZE_MAX_STRING:
            # TODO: Safely escape unsupported characters
            self._match = match
        else:
            assert ValueError, "Match criteria out of range."

    def is_not_test_sensor(self, name: str) -> bool:
        if self._match is not None:
            if 1 >= len(name) <= SANITIZE_MAX_STRING:
                if self._match.lower() in name.lower():
                    return False
                return True
            else:
                assert ValueError, "Name exceeds limit."
        else:
            assert ValueError, "Match criteria not initialized."

    def is_not_monitoring_dc(self, owner: str) -> bool:
        if self._owner is not None and owner is not None:
            if self._owner.lower() is not owner.lower():
                return False
            return True
        else:
            assert ValueError, "Invalid match criteria."


class HttpClient:
    """
    Unified connection configuration handler, connection is setup on initialization of instance. Code should be
    thread-safe.
    """

    _conn_pool: PoolManager = None
    _session = None
    _headers = DEFAULT_REQUEST_HEADERS
    _basic_auth: [str, str] = None
    _session_cookie = None
    _session_cookie_ignore = False
    _session_cookie_issued: datetime = None
    _session_cookie_expires: datetime = None
    _base_url = None
    _req_total: int = 0
    _req_total_in_window: int = 0
    _req_total_start_window: int = 0
    _req_time_start_window: int = None
    _req_last_timestamp: int = None

    def __init__(self, session: (PoolManager, Session), user_name: str = DEFAULT_TRELLIS_USER,
                 user_password: str = None,
                 hostname: str = DEFAULT_TRELLIS_HOST, protocol: str = DEFAULT_CONN_PROTO,
                 port: int = DEFAULT_CONN_PORT):

        # TODO: Some validation of these inputs!
        if user_name is not None and user_password is not None:
            if type(session) is Session:
                self._session = session
            else:
                self._conn_pool = session

            self._basic_auth = (user_name, user_password)
            # self._basic_auth = base64.urlsafe_b64encode(bytes((user_name + ':' + user_password), "utf-8"))
            # self._headers.update({"Authorization", self._basic_auth})
            # TODO: Hostname should be validated for correctness
            # TODO: IPv4 should be validated.
            # TODO: IPv6 should be validated.
            self._generate_base_url(host=hostname, protocol=protocol, port=port)
            self._req_time_start_window = time_ns()
        else:
            assert ValueError, "Credentials not provided."

    def _generate_base_url(self, protocol: str, host: str, port: int = 443):
        """
        Generates the final URL using the initialized hostname, protocol and port assignments.

        :param protocol: This should be http|https (case insensitive as it will be dropped to lower case).
        :param host: This is the hostname, FQDN or IP address for the target Trellis server.
        :param port: This is the TCP port to use on the target server.
        """
        # TODO: The host should really be validated.
        # TODO: Port range should be validated.
        # TODO: Final URL should be verified as safely escaped and correctly coded.
        # TODO: Final URL shoudl be verified for length.
        base_url = (protocol + "://" + host + ":" + str(port) + DEFAULT_API_ROOT)
        logger.debug(("Generated URL: " + base_url.lower()))
        self._base_url = base_url.lower()

    def _prime_session(self):
        logger.debug(("Session Cookie: " + str(self._session_cookie)))
        req = Request(method='HEAD', url=self._base_url, params=None, headers=self._headers)
        req_prep = req.prepare()
        req_prep.prepare_auth(auth=self._basic_auth)
        response: (HTTPResponse, Response) = None

        try:
            response = self._session.send(req_prep)
        except Exception as ex:
            # TODO: Tighten up exception handler
            logger.exception("Failed to prime session.")
            logger.exception(str(ex))

        logger.info("==== prime session cookie ====")

        if (response.status_code == HTTPStatus.OK) or (response.status_code == HTTPStatus.NO_CONTENT):
            logger.debug(("Connection priming response: " + str(response.headers)))
            cookie = response.headers['Set-Cookie']
            if cookie is not None:
                self._headers.update({'Cookie': cookie})
                self._session_cookie = True
                self._session_cookie_issued = time()
            else:
                self._session_cookie = False
            logger.debug("Updated Headers: " + str(self._headers))
        # TODO: Set session expiry time.
        elif (response.status_code == HTTPStatus.FORBIDDEN) or (response.status_code == HTTPStatus.UNAUTHORIZED):
            logger.error(("Connection Status: ", str(response.status_code)))
            logger.error("Please verify authentication credentials.")
            self._session_cookie = False
        else:
            self._session_cookie = False
            logger.error(("Connection Status: ", str(response.status_code)))
            logger.error("Unexpected response from server.")

        logger.info("==== finished priming session cookie ====")

    def _req(self):
        self._req_total += 1
        self._req_last_timestamp = time_ns()

    @on_exception(expo, RateLimitException, max_tries=3)
    @limits(calls=DEFAULT_RATE_LIMIT, period=DEFAULT_RATE_WINDOW)
    def _request_send_limited(self, url: str, query_params: (dict, None)) -> HTTPResponse:
        """
        Send API request to initialized host server, this has enforced rate limiting to prevent impacting QoS for
        application on target host.

        :param url: This is the API portion of the URL only, e.g. /buildings/search/findByNameContaining as the rest
        will be build based on the initialized values.
        :param query_params: Parameters to pass via URL.
        :return: Returns raw response type.
        """
        # TODO: Grab session cookies and feed back into headers
        logger.debug("Request Headers: " + str(self._headers))
        logger.debug("Request URL: " + str(self._base_url + url))
        req = Request(method='GET', url=str(self._base_url + url), params=query_params, headers=self._headers)
        if self._session_cookie is None:
            # TODO: Include session expiry condition for triggering session prime.
            self._prime_session()
            logger.debug("Session cookie generated to authenticate query.")

        req_prep = req.prepare()
        # This seems counter intuitive vs elif, but its to allow for _prime to complete if called.
        if self._session_cookie is False:
            req_prep.prepare_auth(auth=self._basic_auth)
            logger.debug("Basic authorization used to authenticate query.")
        else:
            logger.debug("Session cookie re-used to authenticate query.")

        try:
            response = self._session.send(req_prep)
        except SSLError as ex:
            logger.fatal("Unable to secure connection.")
            logger.exception("OpenSSL Connection failure.")
            logger.exception(str(ex))
            sys.exit(-4)
        except MaxRetryError as ex:
            logger.fatal("Unable to establish connection.")
            logger.exception("Connection retry limit exceeded.")
            logger.exception(str(ex))
            sys.exit(-5)
        except Exception as ex:
            logger.exception("Unhandled exception.")
            logger.exception(str(ex))
            sys.exit(-6)

        logger.debug("Response Status: " + str(response.status_code))
        if DEFAULT_DEBUG_VERBOSITY > 1:
            logger.debug("Response:")
            logger.debug(str(response.text))

        logger.debug("request ended, status={}, elapsed_seconds={}".format(response.status_code,
                                                                           response.elapsed.total_seconds()))
        res: json = response.json()
        return res

    def request_send_without_params(self, url: str) -> HTTPResponse:
        """
        A wrapper to pass through the requests without parameters, strictly speaking this is wholly unnecessary but was
        kept for familiarity. I would propose just passing query_params=None in the calls.

        :param url: This is the API portion of the URL only, e.g. /buildings/search/findByNameContaining as the rest
        will be build based on the initialized values.
        :return: Returns raw response type.
        """
        response = self.request_send(url=url, query_params=None)
        print("request ended, status={}, elapsed_seconds={}".format(response.status_code,
                                                                    response.elapsed.total_seconds()))
        return response

    def request_send(self, url: str, query_params: object) -> json:
        retry_req: bool = False

        try:
            response = self._request_send_limited(url=url, query_params=query_params)
        except RateLimitException:
            logger.error(("Rate limit of " + str(DEFAULT_RATE_LIMIT) + " request per " + str(DEFAULT_RATE_WINDOW) +
                          " seconds exceeded."))
            logger.info("Thread will sleep until rate limit window expires.")
            # TODO: Implement a smarter delay as this is heavy handed.
            sleep(DEFAULT_RATE_WINDOW)
            retry_req = True
            response = []

        if retry_req:
            try:
                response = self._request_send_limited(url=url, query_params=query_params)
            except RateLimitException:
                logger.error("Final retry failed.")
                response = []

        return response


class SanitizeInput:
    """
     Class to handle input sanitization rules, note that these are not validation for acceptability only to ensure content is
     safe.
    """
    def __init__(self, charset: str, accept_escaping: bool = False):
        print("Unimplemented.")
        raise NotImplementedError

    @staticmethod
    def device_name(name: str = None) -> (str, None):
        return None


def get_locations(http_conn: HttpClient, locations: dict) -> (json, None):
    """
    Fetch containers matching locations criteria.

    :param http_conn: urllib3 connection.
    :param locations: User defined search criteria.
    :return:
    """

    if (locations['buildingName'] is not None) and (locations['buildingName'] != ""):
        # TODO: Sanitize for special chars and path traversal.
        query_string = locations['buildingName']

        page = 0
        while True:
            building_param = {
                "name": query_string,
                "projection": "summary,udp",
                "page": page,
                "size": 100,
                "sort": "name"
            }

            buildings: json = http_conn.request_send(PATH_BUILDINGS_SEARCH_FBNIC, building_param)

            page += 1

            if 0 < int(buildings['page']['totalElements']) <= 1:
                for building in buildings['_embedded']['buildings']:
                    print("buildingName: " + building['name'] + "\tbuildingId: " + building['id'])
                    locations['buildingId'] = building['id']
                    locations['buildingName'] = building['name']
            else:
                print("Too many results for building.")
                logger.error("Too many results for building.")

            if page >= buildings['page']['totalPages']:
                break

    '''
    Search for Floor, if Building is provided constrain search by the Building.
    '''
    page = 0
    if (locations['floorName'] is not None) and (locations['floorName'] != ""):

        if locations['buildingId']:
            # TODO:
            while True:
                floor_param = {
                    "projection": "summary,udp",
                    "page": page,
                    "size": 100,
                    "sort": "name"
                }
                path = (PATH_BUILDINGS + locations['buildingId'] + '/floors')
                floors: json = http_conn.request_send(path, floor_param)

                page += 1

                if 0 < int(floors['page']['totalElements']) <= 1:
                    for floor in floors['_embedded']['floors']:
                        if floor['name'].find(locations['floorName']) >= 0:
                            print("floorName: " + floor['name'] + "\tfloorId: " + floor['id'])
                            locations['floorId'] = floor['id']
                            locations['floorName'] = floor['name']
                    if locations['floorId'] is None:
                        locations['floorName'] = None
                        print("Error: Floor not found in building.")
                        logger.error("Floor not found in building.")
                else:
                    print("Too many results for floor.")
                    logger.error("Too many results for floor.")

                if page >= floors['page']['totalPages']:
                    break
        else:
            # TODO: Sanitize for special chars and path traversal.
            query_string = locations['floorName']

            while True:
                floor_param = {
                    "name": query_string,
                    "projection": "summary,udp",
                    "page": page,
                    "size": 100,
                    "sort": "name"
                }

                floors: json = http_conn.request_send(PATH_FLOORS_SEARCH_FBNIC, floor_param)

                page += 1

                if 0 < int(floors['page']['totalElements']) <= 1:
                    for floor in floors['_embedded']['floors']:
                        print("floorName: " + floor['name'] + "\tfloorId: " + floor['id'])
                        locations['floorId'] = floor['id']
                        locations['floorName'] = floor['name']
                else:
                    print("Too many results for floor.")
                    logger.error("Too many results for floor.")

                if page >= floors['page']['totalPages']:
                    break

    '''
    Search for Space, if Floor is provided constrain search by the Floor.
    '''
    page = 0
    if (locations['spaceName'] is not None) and (locations['spaceName'] != ""):
        if locations['floorId'] is not None:
            # TODO:
            while True:
                space_param = {
                    "projection": "summary,udp",
                    "page": page,
                    "size": 100,
                    "sort": "name"
                }
                path = (PATH_FLOORS + locations['floorId'] + '/spaces')
                spaces: json = http_conn.request_send(path, space_param)

                page += 1

                if int(spaces['page']['totalElements']) > 0:
                    for space in spaces['_embedded']['spaces']:
                        if space['name'].find(locations['spaceName']) >= 0:
                            print("spaceName: " + space['name'] + "\tspaceId: " + space['id'])
                            locations['spaceId'] = space['id']
                            locations['spaceName'] = space['name']
                    if locations['spaceId'] is None:
                        locations['spaceName'] = None
                        print("Error: Space not found on floor.")
                        logger.error("Space not found on floor.")
                else:
                    print("No results for space.")
                    logger.error("No results for space.")

                if page >= spaces['page']['totalPages']:
                    break
        elif (locations['floorId'] is None) and (locations['buildingId'] is not None):
            # TODO
            print("Error: Unimplemented search criteria of building & space without floor.")
            logger.error("Error: Unimplemented search criteria of building & space without floor.")
        else:
            # TODO: Sanitize for special chars and path traversal.
            query_string = locations['spaceName']

            while True:
                space_param = {
                    "name": query_string,
                    "projection": "summary,udp",
                    "page": page,
                    "size": 100,
                    "sort": "name"
                }

                spaces: json = http_conn.request_send(PATH_SPACES_SEARCH_FBNIC, space_param)

                page += 1

                if 0 < int(spaces['page']['totalElements']) <= 1:
                    for floor in floors['_embedded']['spaces']:
                        print("spaceName: " + floor['name'] + "\tspaceId: " + floor['id'])
                        locations['spaceId'] = floor['id']
                        locations['spaceName'] = floor['name']
                else:
                    print("Too many results for floor.")
                    logger.error("Too many results for floor.")

                if page >= spaces['page']['totalPages']:
                    break

    return locations


def get_modules(http_conn: HttpClient, device: str) -> (json, None):
    """
       Generate a list of buildings that should be queried.

       Changes - Modified to use findByOwner API call instead, the loop will still verify other match criteria but
       result set to process is less.

       :param device: List of devices to fetch child items.
       :param http_conn: urllib3 session
       :return:
    """
    page = 0

    # Verify total results before attempting to process them.
    path = (PATH_DEVICES + device + "/devices/")
    params = {
        "projection": "summary",
        "page": page,
        "size": 100,
        "sort": "name"
    }

    modules: json = http_conn.request_send(path, params)
    module_list: list = []

    if int(modules['page']['totalElements']) > 0:
        while True:
            # Changed projection to summary as ~50% less payload size than all.
            params = {
                "page": page,
                "size": 100,
                "projection": "summary,udp",
                "sort": "name"
            }

            devices = http_conn.request_send(path, params)

            page += 1
            for device in devices['_embedded']['devices']:
                module_list.append({
                    'id': device['id'],
                    'name': device['name'],
                    'categories': device['categories']
                })

            if page >= devices['page']['totalPages']:
                break
    else:
        logger.info("No results to process.")
        return None

    return module_list


def get_ports(http_conn: HttpClient, device: list) -> (json, None):
    """
       Generate a list of buildings that should be queried.

       Changes - Modified to use findByOwner API call instead, the loop will still verify other match criteria but
       result set to process is less.

       :param device: List of devices to fetch child items.
       :param http_conn: urllib3 session
       :return:
    """

    # Verify total results before attempting to process them.
    path = (PATH_DEVICES + device + "/")
    params = {
        "projection": "openings",
        "sort": "label,asc"
    }

    ports = http_conn.request_send(path, params)
    ports_list: list = []

    for port in ports['openings']:
        if str(port['type']).upper() == "DATA":
            ports_list.append({
                'type': port['type'],
                'label': port['label'],
                'portType': port['portType'],
                'connectorType': port['connectorType'],
                'connectedStatus': port['connectedStatus'],
                'media': port['media'],
                'teaming': port['teaming'],
                'id': port['id']
            })

    # Sort the output, note that sorted orders on first number.
    return natsorted(ports_list, key=lambda k: k.get('label', 0), reverse=False)


def get_slots(http_conn: HttpClient, devices: list) -> (json, None):
    return None


def get_switches(http_conn: HttpClient, racks: dict, limit: (int, None) = None) -> (json, None):
    """
    Fetch switches in specified racks.

    :param http_conn: urllib3 connection.
    :param racks: User defined racks.
    :param limit: Limit the number of results to process.
    :return: JSON payload for matching switches.
    """

    devices = []

    for rack in racks:
        page: int = 0

        query_string: str = "(rackId==" + rack['id'] + \
                            " and (displayCategoryProgrammaticName==CHASSIS or displayCategoryProgrammaticName==NETWORK_SWITCH))"
        logger.debug("Generated query string: " + query_string)

        # Use API sort to lazy sort results (note that this is inverted)
        if rack['isRuScaleTopDown']:
            sort_order = "rackUPosition,asc"
        else:
            sort_order = "rackUPosition,desc"

        while True:
            rack_param = {
                "query": query_string,
                "projection": "all",
                # "projection": "basic,slots,placements,alarms,openings,udp",
                "page": page,
                "size": 100,
                "sort": sort_order
            }

            result: json = http_conn.request_send(PATH_DEVICES_SEARCH_FBQ, rack_param)

            page += 1
            count = 0
            for device in result['_embedded']['devices']:
                count += 1
                if (limit is None) or (count <= limit):
                    devices.append(device)

            if page >= result['page']['totalPages']:
                break

    print("Matching Switches: " + str(len(devices)))

    # TODO: Add filtering criteria for switches here and remove entries that do not match.

    return devices


def get_racks(http_conn: HttpClient, location: (dict, list, json)) -> (json, None):
    """
    Fetch racks in containers.

    :param http_conn: urllib3 connection.
    :param location: User defined location criteria.
    :return:
    """

    page: int = 0
    locations: dict
    devices = []

    '''
    Fall through logic, must process in order building, floor, space to zone.
    '''
    query_string: str = "((displayCategoryProgrammaticName==RACK or displayCategoryProgrammaticName==CABINET)"
    if location['buildingId'] or location['floorId'] or location['spaceId'] or location['zoneId']:
        query_string += " and ("
        if location['buildingId']:
            query_string += "buildingId==" + location['buildingId']
            if location['floorId'] or location['spaceId'] or location['zoneId']:
                query_string += " and "
        if location['floorId']:
            query_string += "floorId==" + location['floorId']
            if location['spaceId'] or location['zoneId']:
                query_string += " and "
        if location['spaceId']:
            query_string += "spaceId==" + location['spaceId']
            if location['zoneId']:
                query_string += " and "
        if location['zoneId']:
            query_string += "zoneId==" + location['zoneId']

    if ((location['buildingId'] or
         location['floorId'] or
         location['spaceId'] or
         location['zoneId']) and location['rackName']):
        query_string += ") and name==\"*" + location['rackName'] + "*\")"
    else:
        query_string += ")"

    logger.debug("get_racks(): queryString: " + query_string)

    while True:
        location_params = {
            "query": query_string,
            "projection": "basic,search",
            "page": page,
            "size": SANITIZE_MAX_PAGE_SIZE
        }

        result: json = http_conn.request_send(PATH_DEVICES_SEARCH_FBQ, location_params)

        page += 1

        i: int = 0
        for device in result['_embedded']['devices']:
            devices.append({
                "id": device['id'],
                "name": device['name'],
                "startingRU": device['specificProperties']['rack']['startingRU'],
                "isRuScaleTopDown": device['specificProperties']['rack']['isRuScaleTopDown']
            })

        if page >= result['page']['totalPages']:
            break

    print("Matching Racks: " + str(result['page']['totalElements']))

    return devices


def get_buildings(http_conn: HttpClient, match_criteria: dict) -> (json, None):
    """
    Generate a list of buildings that should be queried.

    Changes - Modified to use findByOwner API call instead, the loop will still verify other match criteria but result set to
    process is less.

    :param match_criteria: Building owner name (default '').
    :param http_conn: urllib3 session
    :return:
    """
    page = 0
    test = TestCriteria(owner=match_criteria['owner'])

    # Verify total results before attempting to process them.
    find_by_owner = "buildings/search/findByOwnerIsContaining"
    params = {
        "owner": match_criteria['owner'],
        "page": 0,
        "size": BUILDINGS_PAGE_SIZE,
        "projection": "summary",
    }
    buildings: json = http_conn.request_send(find_by_owner, params)
    building_list: dict = {}

    if DEFAULT_DEBUG_VERBOSITY > 1:
        logger.debug("Query response:")
        logger.debug(str(type(buildings)))
        logger.debug(str(buildings))

    print("buildings: " + json.dumps(buildings))
    if int(buildings['page']['totalElements']) > 0:
        while True:
            # Changed projection to summary as ~50% less payload size than all.
            building_params = {
                "owner": match_criteria['owner'],
                "page": page,
                "size": BUILDINGS_PAGE_SIZE,
                "projection": "all",
            }

            result = http_conn.request_send(find_by_owner, building_params)

            logger.debug(("Total Results: " + str(result['page']['totalElements'])))
            logger.debug(("Total Pages: " + str(result['page']['totalPages'])))
            if DEFAULT_DEBUG_VERBOSITY > 1:
                logger.debug(json.dumps(result))
            page += 1

            i: int = 0
            for building in result['_embedded']['buildings']:
                if not test.is_not_monitoring_dc(building['owner']):
                    building_list.update({
                        i: {
                            "id": building['id'],
                            "name": building['name'],
                        }
                    })
                    i += 1

            if page >= result['page']['totalPages']:
                break
    else:
        logger.info("No results to process.")

    logger.debug(("Matched Building: " + str(building_list)))
    return building_list


def extract_values(obj, key):
    '''
    Pull all values of specified key from nested JSON.
    Ref. https://hackersandslackers.com/extract-data-from-complex-json-python/

    '''
    arr = []

    def extract(obj, arr, key):
        """Recursively search for values of key in JSON tree."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    extract(v, arr, key)
                elif k == key:
                    arr.append(v)
        elif isinstance(obj, list):
            for item in obj:
                extract(item, arr, key)
        return arr

    results = extract(obj, arr, key)
    return results


def main(arguments):
    """
    Entry point.

    :param arguments: Arguments passed at runtime.
    :return:
    """
    _hostname: str = DEFAULT_TRELLIS_HOST
    _port: int = 443
    _protocol: str = DEFAULT_CONN_PROTO
    _username: str = DEFAULT_TRELLIS_USER
    _password: (str, None) = None
    _criteria: dict = {
        'owner': DEFAULT_MATCH_OWNER,
        'name': DEFAULT_MATCH_NAME,
        'buildingName': None,
        'floorName': None,
        'spaceName': None,
        'zoneName': None
    }

    locations: dict = dict.fromkeys(
        [
            'buildingId',
            'buildingName',
            'floorId',
            'floorName',
            'spaceId',
            'spaceName',
            'zoneId',
            'zoneName',
            'name'
        ])

    # session = PoolManager()
    session = Session()
    session.headers.update({'Content-type': 'application/hal+json', 'Accept': 'application/hal+json'})

    print("==== Processing Arguments ====")
    logger.info("==== Processing Arguments ====")
    logger.debug('Arguments ' + str(arguments))

    if 0 < len(arguments.host) <= 65535:
        _hostname = str(arguments.host).lower()
        logger.debug(("Hostname: " + _hostname))
    else:
        logger.debug("Hostname length: " + str(len(arguments.host)))
        assert ValueError, ("Invalid hostname " + _hostname + " provided.")
        logger.error(("Invalid hostname " + _hostname + " provided."))
        # TODO: Enumerate exit codes for script.
        return sys.exit(-1)

    if 0 < arguments.port <= 65535:
        _port = arguments.port
    else:
        assert ValueError, ("Port assignment " + str(_port) + " out of range.")
        logger.error("Port assignment out of range, falling back to default (" + str(_port) + ").")

    if str(arguments.protocol).lower() == 'http':
        logger.warning(
            "HTTP connectivity is insecure, care should be taken when used to avoid leakage of data and/or credentials.")
        assert NotImplementedError, "HTTP support is presently unimplemented, please use HTTPS."
        logger.error("HTTP support is presently unimplemented, please use HTTPS.")
        return sys.exit(-2)
    else:
        _protocol = str(arguments.protocol).lower()

    if 0 < len(arguments.user) <= 253:
        # TODO: Implement more checks for user input.
        _username = str(arguments.user)
    else:
        assert ValueError, ("Invalid username " + _username + " provided.")
        logger.error(("Invalid username " + _username + " provided."))
        # TODO: Enumerate exit codes for script.
        return sys.exit(-3)

    if arguments.password is None:
        _password = getpass.getpass(prompt=("Please enter password for " + _username + ":"))
        logger.info("User prompted for password.")
    elif 0 < len(arguments.password) <= 253:
        # TODO: Implement more checks for user input.
        _password = str(arguments.password)
    else:
        assert ValueError, ("[Fatal]: Invalid password " + _password + " provided.")
        logger.fatal(("Invalid username " + _password + " provided."))
        # TODO: Enumerate exit codes for script.
        return sys.exit(-3)

    if arguments.insecure is True:
        logger.warning("HTTPS validation is suppressed, this can be insecure.")
        session.verify = False
    else:
        session.verify = True

    #if 0 < len(arguments.owner) <= 253:
    #    # TODO: Validate string is only Trellis accepted chars.
    #    _criteria['owner'] = arguments.owner

    if 0 < len(arguments.rack_name) <= 253:
        # TODO: Validate string is only Trellis accepted chars.
        locations['rackName'] = arguments.rack_name

    if 0 < len(arguments.device_name) <= 253:
        # TODO: Validate string is only Trellis accepted chars.
        locations['device_name'] = arguments.device_name

    if 0 < len(arguments.building) <= 253:
        # TODO: Validate string is only Trellis accepted chars.
        locations['buildingName'] = arguments.building

    if 0 < len(arguments.floor) <= 253:
        # TODO: Validate string is only Trellis accepted chars.
        locations['floorName'] = arguments.floor

    if 0 < len(arguments.space) <= 253:
        # TODO: Validate string is only Trellis accepted chars.
        locations['spaceName'] = arguments.space

    if 0 < len(arguments.zone) <= 253:
        # TODO: Validate string is only Trellis accepted chars.
        locations['zoneName'] = arguments.zone

    if arguments.limit is not None:
        try:
            tmp: int = int(arguments.limit)
            if 0 < tmp <= SANITIZE_RESULT_LIMIT:
                tor_limit = int(arguments.limit)
            else:
                tor_limit = SANITIZE_RESULT_LIMIT
        except ValueError:
            print("[Error]: Invalid limit provided, it must be a positive integer between 1 and " +
                  str(SANITIZE_RESULT_LIMIT) + ".")
            logger.error("[Error]: Invalid limit provided, it must be a positive integer between 1 and " +
                         str(SANITIZE_RESULT_LIMIT) + ".")
            tor_limit = None
    else:
        tor_limit = None

    # TODO: Implement client key handler.
    # session.cert = ('.pki/keys/client-cert.pem', '.pki/keys/private-key.pem')

    print("==== Initializing Connection ====")
    logger.info("==== Initializing Connection ====")

    try:
        http_conn = HttpClient(session=session, user_name=_username, user_password=_password, hostname=_hostname,
                               port=_port, protocol=_protocol)
    except (ValueError, SSLError, MaxRetryError) as ex:
        print("[Fatal]: Failed to initialize connection with Trellis server. Please verify host and credentials.")
        logger.fatal("Failed to initialize connection with Trellis server. Please verify host and credentials.")
        logger.exception(ex)
        sys.exit(-4)

    print("==== Resolving Locations ====")
    logger.info("==== Resolving Locations ====")

    locations = get_locations(http_conn, locations)

    # get all buildings
    start_process_time: float = process_time()
    start_real_time: float = perf_counter()

    print("==== Resolving Racks ====")
    logger.info("==== Resolving Racks ====")
    racks = get_racks(http_conn, locations)

    print("==== Resolving Devices ====")
    logger.info("==== Resolving Devices ====")
    switches = get_switches(http_conn, racks, tor_limit)

    print("\n==== Results ====\n")

    for switch in switches:
        print("\t--- " + str(switch['name']) + " ---")
        print("\tSwitch Name: " + str(switch['name']) + "\tSwitch ID: " + str(switch['id']))
        print("\tLocation: " + switch['location'])
        print("\tManufacturer: " + str(switch['manufacturer']) + "\tModel: " + str(
            switch['model']) + "\tModel Qualifier: " + str(switch['modelQualifier']))
        print("\tRack U: " + str(switch['rackUPosition']) + "\tPhysical Placement: " + str(
            switch['physicalPlacement']['side']))

        modules = get_modules(http_conn, switch['id'])

        # TODO: This is really poor quality code, I need to replace with recursive code to ensure this is more flexible.
        if modules is not None:
            # Process ports (openings on switch)
            print()
            for module in modules:
                print("\tModule Name: " + module['name'] + "\tModule ID: " + module['id'])
                cards = get_modules(http_conn, module['id'])
                if cards is not None:
                    for card in cards:
                        print("\tCard Name: " + card['name'] + "\tCard ID: " + card['id'])
                        port_list = get_ports(http_conn, card['id'])
                        print(port_list)
                        for port in port_list:
                            if str(port['portType']).upper() == "NETWORK":
                                print('\t\tPort Label: ' + port['label'] + ' \tPort Type: ' + port['portType'] +
                                      ' (' + port['connectorType'] + ')')

                port_list = get_ports(http_conn, module['id'])
                if port_list is not None:
                    for port in port_list:
                        if str(port['portType']).upper() == "NETWORK":
                            print('\t\tPort Label: ' + str(port['label']).capitalize() + ' \tPort Type: ' +
                                  str(port['portType']).capitalize() + ' (' + port['connectorType'] + ')')
                    print()
        else:
            # Process ports (openings on switch)
            print()
            port_list = get_ports(http_conn, switch['id'])
            if port_list is not None:
                for port in port_list:
                    if str(port['portType']).upper() == "NETWORK":
                        print('\t\tPort Label: ' + str(port['label']).capitalize() + ' \tPort Type: ' +
                                str(port['portType']).capitalize() + ' (' + port['connectorType'] + ')')
                print()

        print("\n")

    logger.info("=== Complete ===")

    elapsed_process_time: float = process_time() - start_process_time
    elapsed_real_time: float = perf_counter() - start_real_time

    logger.info(("Duration: process_time={}s real_time={}s".format(elapsed_process_time, elapsed_real_time)))


if __name__ == '__main__':
    """
    Modified loader to setup logging prior to launching main().
    """

    # TODO: Prepare sample configuration for syslog output.
    if os.path.exists('./logging.conf'):
        logging.config.fileConfig('./logging.conf')
    else:
        logging.basicConfig(filename=('trellis-datapoint-sync_' + strftime('%Y%m%d-%H%M%S%z') + '.log'), filemode='w',
                            level=logging.DEBUG,
                            format='%(module)s (%(process)s) %(levelname)s %(asctime)s %(message)s',
                            datefmt='%Y%m%d-%H:%M:%S%z')
    logger = logging.getLogger(__name__)

    if DEFAULT_DEBUG_VERBOSITY > 1:
        logger.setLevel(logging.DEBUG)

    logger.info("Logging started.")
    #####

    arg_parser = argparse.ArgumentParser(description="Vertiv™ Trellis™ Enterprise - Data Point Parser")
    arg_parser.add_argument('--insecure', help='Disable HTTPS validations.', action='store_true')
    arg_parser.add_argument('-t', '--host', help='Trellis(tm) hostname.', type=str, default=DEFAULT_TRELLIS_HOST)
    arg_parser.add_argument('-p', '--protocol', help='Protocol HTTP|HTTPS', type=str, choices=['http', 'https'],
                            default=DEFAULT_CONN_PROTO)
    arg_parser.add_argument('-P', '--port', help='TCP port', type=int, default=DEFAULT_CONN_PORT)
    arg_parser.add_argument('-u', '--user', help='Authenticating user name.', type=str, default=DEFAULT_TRELLIS_USER)
    arg_parser.add_argument('-a', '--password',
                            help='Authenticating user password (not recommended to pass as parameter).', type=str,
                            default=None)
    arg_parser.add_argument('-k', '--key', help='Client private key.', type=str, default='.pki/keys/private-key.pem')
    arg_parser.add_argument('-C', '--cert', help='Client public certificate.', type=str,
                            default='.pki/keys/client-cert.pem')
    arg_parser.add_argument('-D', '--datapoint-tags', nargs='+', help='Device dpProgrammaticName values to return.',
                            required=False, default=def_proc)

    arg_group_api = arg_parser.add_argument_group()
    arg_group_api.add_argument('--set-pagesize', help='Set results per response page.', type=int, default=100)

    arg_group_criteria = arg_parser.add_argument_group()
    arg_group_criteria.add_argument('-n', '--rack-name', help='The parent rack/cabinet name contents must match.',
                                    type=str,
                                    default=DEFAULT_MATCH_NAME)
    arg_group_criteria.add_argument('-N', '--device-name', help='The child device name contents must contain.', type=str,
                                    default=DEFAULT_MATCH_NAME)
    #arg_group_criteria.add_argument('-o', '--owner', help='The owner must contain.', type=str,
    #                                default=DEFAULT_MATCH_OWNER)
    arg_group_criteria.add_argument('-b', '--building', help='The building name contains.', type=str,
                                    default="")
    arg_group_criteria.add_argument('-f', '--floor', help='The floor name contains.', type=str,
                                    default="")
    arg_group_criteria.add_argument('-s', '--space', help='The space name contains.', type=str,
                                    default="")
    arg_group_criteria.add_argument('-z', '--zone', help='The zone name contains.', type=str,
                                    default="")
    arg_group_criteria.add_argument('-l', '--limit', help='Limit the number of switches returned.',
                                    default=None)

    args = arg_parser.parse_args()
    logger.debug('Arguments ' + str(args))

    main(args)
