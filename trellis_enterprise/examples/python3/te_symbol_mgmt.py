import argparse
import getpass
import sys
import uuid
import os
import json
import urllib3
import logging.config
import demjson
import timeit
from ratelimit import limits, RateLimitException
from backoff import on_exception, expo
from http import HTTPStatus
from datetime import datetime, timedelta
from time import process_time, process_time_ns, perf_counter, perf_counter_ns, sleep, time_ns, time, strftime
from requests import Request, Session, Response
from urllib3 import PoolManager, HTTPResponse
from urllib3.exceptions import InsecureRequestWarning, HTTPError, SSLError, MaxRetryError

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

DEFAULT_DEBUG_VERBOSITY = 2     # 1: Normal debug output, 2: Adds raw payload output.

"""
API Paths
"""
PATH_DATA_POINT_DEFS = 'datapointdefinitions/search/findDatapointDefinitionsByDevice'
PATH_DATA_POINTS = 'datapoints/search/getTimeseriesData'
# PATH_DEVICES_SEARCH_FBNICAOCPNIC = 'devices/search/findByObjectCategoryProgrammaticName'
PATH_DEVICES_SEARCH_FBNICAOCPNIC = 'devices/search/findByNameIsContainingAndObjectCategoryProgrammaticNameIsContaining'
PATH_BUILDINGS = 'buildings'
PATH_BUILDINGS_SEARCH_FBQ = 'buildings/search/findByQuery'
PATH_DEVICES_SEARCH_FBQ = 'devices/search/findByQuery'
PATH_SYMBOLS_SEARCH_FBLSV = 'symbols/search/findByLatestSymbolVersion'
PATH_SYMBOLS_ALL = 'symbols/'
PATH_SYMBOLS_SEARCH_FBTIT = 'symbols/search/findBytypeIdentifierTag'


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
SANITIZE_MAX_URL = 2000         # While RFC 2616 is unbounded, safe limit is generally considered 2000 (2083 for IE).
SANITIZE_MAX_HOSTNAME = 250     # RFC 1035 assuming single . and null with label.
SANITIZE_MAX_HOSTNAME_LABEL = 63
SANITIZE_MAX_PAGE_SIZE = 1000   # Trellis 4.0.3+ constrains results per page to 1000



class SymbolType:
	def __init__(self):
		assert isinstance(display_category_programmatic_name, (str, None))
		assert isinstance(symbol_minor_version, (int, None))
		assert isinstance(symbol_minor_version, (int, None))
		assert isinstance(manufacturer, (str, None))
		assert isinstance(model_qualifier, (str, None))
		assert isinstance(productLine, (str, None))
		assert isinstance(type_identifier_tag, (str, None))
		assert isinstance(model, (str, None))
		assert isinstance(is_newest, (bool, None))
		assert isinstance(newest_id, (int, None))

		self.display_category_programmatic_name = None
		self.symbol_major_version = None
		self.symbol_minor_version = None
		self.manufacturer = None
		self.model_qualifier = None
		self.productLine = None
		self.type_identifier_tag = None
		self.model = None
		self.is_newest = None
		self.newest_id = None

	# def set_type_identifier_tag(self, symbol_type_ident: str):
	#     self.type_identifier_tag = symbol_type_ident
	#
	# def set_major_ver(self, symbol_ver: str):
	#     self.symbol_major_version = symbol_ver
	#
	# def set_minor_ver(self, symbol_ver: str):
	#     self.symbol_minor_version = symbol_ver
	#
	# def set_is_newest(self, symbol_newest: bool):
	#     self.is_newest = symbol_newest
	#
	# def set_newest_id(self, symbol_replmnt: int):
	#     self.newest_id = symbol_replmnt


class NodeType:
	symbol_latest: (str, None) = None
	symbol_usage: int = 0

	def __init__(self, symbol_typeid: str = None, symbol_latest: bool = True, symbol_version: str = None):
		self.symbol_typeid = symbol_typeid
		if symbol_latest:
			self.symbol_latest: str = symbol_version
		self.left_child = None
		self.right_child = None


class SymbolBinarySearchTree:
	def __init__(self):
		self.root = None

	def insert(self, symbol_type_id: str, symbol_latest: bool, symbol_version: str):
		if self.root is None:
			self.root = NodeType(symbol_type_id, symbol_latest, symbol_version)
			# self.root.symbol = symbol_t(symbol)
		else:
			self._insert(symbol_type_id, self.root, symbol_latest, symbol_version)

	def _insert(self, symbol_type_id, cur_node, symbol_latest: bool, symbol_version: str):
		if symbol_type_id < cur_node.symbol_typeid:
			if cur_node.left_child is None:
				cur_node.left_child = NodeType(symbol_type_id, symbol_latest, symbol_version)
				# cur_node.left_child.symbol = symbol_t(symbol)
			else:
				self._insert(symbol_type_id, cur_node.left_child, symbol_latest, symbol_version)
		elif symbol_type_id > cur_node.symbol_typeid:
			if cur_node.right_child is None:
				cur_node.right_child = NodeType(symbol_type_id, symbol_latest, symbol_version)
				# cur_node.right_child.symbol = symbol_t(symbol)
			else:
				self._insert(symbol_type_id, cur_node.right_child, symbol_latest, symbol_version)
		else:
			logger.warning("Value already in tree.")

	def print_tree(self):
		if self.root is not None:
			self._print_tree(self.root)

	def _print_tree(self, cur_node):
		if cur_node is not None:
			self._print_tree(cur_node.left_child)
			print("symbolTypeId: " + str(cur_node.symbol_typeid) + " \tLatest Version: " + str(cur_node.symbol_latest))
			logger.debug(str(cur_node.symbol_typeid))
			self._print_tree(cur_node.right_child)

	def height(self):
		if self.root is not None:
			return self._height(self.root, 0)
		else:
			return 0

	def _height(self, cur_node, cur_height):
		if cur_node is None:
			return cur_height
		left_height = self._height(cur_node.left_child, cur_height + 1)
		right_height = self._height(cur_node.right_child, cur_height + 1)
		return max(left_height, right_height)

	def search_by_typeid(self, symbol_type_id: int) -> bool:
		if self.root is not None:
			return self._search_by_typeid(symbol_type_id, self.root)
		else:
			return False

	def _search_by_typeid(self, symbol_type_id: int, cur_node) -> bool:
		if symbol_type_id == cur_node.symbol_typeid:
			return True
		elif symbol_type_id < cur_node.symbol_typeid and cur_node.left_child is not None:
			return self._search_by_typeid(symbol_type_id, cur_node.left_child)
		elif symbol_type_id > cur_node.symbol_typeid and cur_node.right_child is not None:
			return self._search_by_typeid(symbol_type_id, cur_node.right_child)
		else:
			return False


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

	def __init__(self, session: (PoolManager, Session), user_name: str = DEFAULT_TRELLIS_USER, user_password: str = None,
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
		logger.debug(("Request URL: " + str(self._base_url + url)))
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

		logger.debug("request ended, status={}, elapsed_seconds={}".format(response.status_code, response.elapsed.total_seconds()))
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
		retry_req = False
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

def get_symbol_mult_ver(http_conn: HttpClient, symbols: SymbolBinarySearchTree, page_size: int = 100) -> (SymbolBinarySearchTree, None):
	"""
	Process list of symbols and extract those that have more than one version installed.
	"""
	for symbol in symbols:


def get_symbols(http_conn: HttpClient, latest_only: bool = True, page_size: int = 100) -> (SymbolBinarySearchTree, None):
	"""
	Fetch switches in specified racks.

	:param http_conn: urllib3 connection.
	:param racks: User defined racks.
	:return: JSON payload for matching switches.
	"""

	symbols_tree: SymbolBinarySearchTree = SymbolBinarySearchTree()

	page: int = 0

	if latest_only:
		PATH_SYMBOLS_TMP = PATH_SYMBOLS_SEARCH_FBLSV
	else:
		PATH_SYMBOLS_TMP = PATH_SYMBOLS_ALL

	while True:
		symbol_param = {
			"projection": "summary",
			"page": page,
			"size": page_size,
			"sort": "recordCreateDate,asc"
			}

		result: json = http_conn.request_send(PATH_SYMBOLS_TMP, symbol_param)

		print('Page ' + str(page) + ' of ' + str(result['page']['totalPages']))

		page += 1
		
		for symbol in result['_embedded']['symbols']:
			symbol_version = symbol['symbolMajorVersion'] + "." + symbol['symbolMinorVersion']
			# print("==== Symbol ====")
			# print("\tmanufacturer:" + symbol['manufacturer'] + " \tmodel: " + symbol['model'] + " \tmodelQualifier: " + symbol['modelQualifier'])
			# print("\ttypeIdentifierTag: " + symbol['typeIdentifierTag'] + " \tVersion: " + symbol_version)
			symbols_tree.insert(symbol['typeIdentifierTag'], latest_only, symbol_version)

		if page >= result['page']['totalPages']:
			break
	
	return symbols_tree

	
def get_racks(http_conn: HttpClient, location: dict) -> (json, None):
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
	queryString: str = "((displayCategoryProgrammaticName==RACK or displayCategoryProgrammaticName==CABINET)"
	if (location['buildingId'] or location['floorId'] or location['spaceId'] or location['zoneId']):
		queryString += " and ("
		if location['buildingId']:
			queryString += "buildingId=="+ location['buildingId']
			if (location['floorId'] or location['spaceId'] or location['zoneId']):
				queryString += " and "
		if location['floorId']: 
			queryString += "floorId==" + location['floorId']
			if (location['spaceId'] or location['zoneId']):
				queryString += " and "
		if location['spaceId']:
			queryString += "spaceId==" + location['spaceId']
			if (location['zoneId']):
				queryString += " and "
		if location['zoneId']:
			queryString += "zoneId==" + location['zoneId']
	
	if ((location['buildingId'] or location['floorId'] or location['spaceId'] or location['zoneId']) and location['name']):
		queryString += ") and name==\"*" + location['name'] + "*\")"
	else:
		queryString += "))"

	logger.debug("Generated query string: "  + queryString)

	while True:
		location_params = {
			"query" : queryString,
			"projection": "basic,search",
			"page": page,
			"size": SANITIZE_MAX_PAGE_SIZE
			}
				
		result: json = http_conn.request_send(PATH_DEVICES_SEARCH_FBQ, location_params)
		
		page += 1
		
		i: int = 0
		for device in result['_embedded']['devices']:
			devices.append({
			#	i : {
					"id": device['id'],
					"name": device['name']}
			)
			#//i += 1
		
		if page >= result['page']['totalPages']:
			break

	print("Matching Racks: " + str(i))
			
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

	if buildings['page']['totalElements'] > 0:
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
						i : {
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
	"""Pull all values of specified key from nested JSON.
	Ref. https://hackersandslackers.com/extract-data-from-complex-json-python/
	"""
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
	_password: str = None
	_criteria: dict = {
		'owner': DEFAULT_MATCH_OWNER,
		'name': DEFAULT_MATCH_NAME,
		'building': None,
		'floor': None,
		'space': None,
		'zone' : None
	}

	# session = PoolManager()
	session = Session()
	session.headers.update(
		{'Content-type': 'application/hal+json',
		 'Accept': 'application/hal+json'}
	)

	print("==== processing arguments ====")
	logger.info("==== processing arguments ====")
	logger.debug('Arguments ' + str(arguments))

	if 0 < len(arguments.host) <= 65535:
		_hostname = str(arguments.host).lower()
		logger.debug(("Hostname: " + _hostname))
	else:
		logger.debug(("Hostname length: " + str(len(arguments.host))))
		assert ValueError, ("Invalid hostname " + _hostname + " provided.")
		logger.error(("Invalid hostname " + _hostname + " provided."))
		# TODO: Enumerate exit codes for script.
		return sys.exit(-1)

	if 0 < arguments.port <= 65535:
		_port = arguments.port
	else:
		assert ValueError, ("Port assignment " + _port + " out of range.")
		logger.error("Port assignment out of range, falling back to default (" + _port + ").")

	if str(arguments.protocol).lower() == 'http':
		logger.warning("HTTP connectivity is insecure, care should be taken when used to avoid leakage of data and/or credentials.")
		assert NotImplementedError, "HTTP support is presently unimplemented, please use HTTPS."
		logger.error( "HTTP support is presently unimplemented, please use HTTPS.")
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
		assert ValueError, ("Invalid password " + _password + " provided.")
		logger.error(("Invalid username " + _password + " provided."))
		# TODO: Enumerate exit codes for script.
		return sys.exit(-3)

	if arguments.insecure is True:
		logger.warning("HTTPS validation is suppressed, this can be insecure.")
		session.verify = False
	else:
		session.verify = True

	if 0 < len(arguments.match_owner) <=253:
		# TODO: Validate string is only Trellis accepted chars.
		_criteria['owner'] = arguments.match_owner

	if 0 < len(arguments.match_name) <= 253:
		# TODO: Validate string is only Trellis accepted chars.
		_criteria['name'] = arguments.match_name

	if 0 < len(arguments.building) <= 253:
		# TODO: Validate string is only Trellis accepted chars.
		_criteria['building'] = arguments.building

	if 0 < len(arguments.floor) <= 253:
		# TODO: Validate string is only Trellis accepted chars.
		_criteria['floor'] = arguments.floor

	if 0 < len(arguments.space) <= 253:
		# TODO: Validate string is only Trellis accepted chars.
		_criteria['space'] = arguments.space

	if 0 < len(arguments.zone) <= 253:
		# TODO: Validate string is only Trellis accepted chars.
		_criteria['zone'] = arguments.zone

	
	if (0 < arguments.set_pagesize < SANITIZE_MAX_PAGE_SIZE):
		api_pagesize = arguments.set_pagesize
	else:
		api_pagesize = DEFAULT_PAGE_SIZE  # type: int

	logger.debug(("Match criteria: " + str(_criteria)))

	# TODO: Implement client key handler.
	# session.cert = ('.pki/keys/client-cert.pem', '.pki/keys/private-key.pem')

	print("==== Initializing Connection ====")
	logger.info("==== Initializing connection ====")

	try:
		http_conn = HttpClient(session=session, user_name=_username, user_password=_password, hostname=_hostname,
						   port=_port, protocol=_protocol)
	except:
		print("Connection failure.")
		return
	
	# Get Latest Symbols
	start_process_time: float = process_time()
	start_real_time: float = perf_counter()


	print("==== Get Latest Symbols Start! ====")
	logger.info("==== Get Latest Symbols Start! ====")

	latest_symbols: SymbolBinarySearchTree = get_symbols(http_conn, latest_only = True, page_size = api_pagesize)
	latest_symbols.print_tree()
	
	#print("==== Get Latest Symbols End! Count={} ====".format(str(latest_symbols.size())))
	#logger.info(("==== Get Latest Symbols End! Count={} ====".format(str(latest_symbols.size()))))

	# print("Total Symbols: " + str(latest_symbols.height()))

	print("\n==== Results ====\n")

	logger.info("=== complete ===")

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
	arg_parser.add_argument('-p', '--protocol', help='Protocol HTTP|HTTPS', type=str, choices=['http', 'https'], default=DEFAULT_CONN_PROTO)
	arg_parser.add_argument('-P', '--port', help='TCP port', type=int, default=DEFAULT_CONN_PORT)
	arg_parser.add_argument('-u', '--user', help='Authenticating user name.', type=str, default=DEFAULT_TRELLIS_USER)
	arg_parser.add_argument('-a', '--password', help='Authenticating user password (not recommended to pass as parameter).', type=str, default=None)
	arg_parser.add_argument('-k', '--key', help='Client private key.', type=str, default='.pki/keys/private-key.pem')
	arg_parser.add_argument('-C', '--cert', help='Client public certificate.', type=str, default='.pki/keys/client-cert.pem')
	arg_parser.add_argument('-D', '--datapoint-tags', nargs='+', help='Device dpProgrammaticName values to return.', required=False, default=def_proc)

	arg_group_api = arg_parser.add_argument_group()
	arg_group_api.add_argument('--set-pagesize', help='Set results per response page.', type=int, default=100)

	arg_group_criteria = arg_parser.add_argument_group()
	arg_group_criteria.add_argument('-n', '--match-name', help='The name contents must match.', type=str,
									default=DEFAULT_MATCH_NAME)
	arg_group_criteria.add_argument('-o', '--match-owner', help='The owner must match.', type=str,
									default=DEFAULT_MATCH_OWNER)
	arg_group_criteria.add_argument('-b', '--building', help='The building name contains.', type=str,
									default="")
	arg_group_criteria.add_argument('-f', '--floor', help='The floor name contains.', type=str,
									default="")
	arg_group_criteria.add_argument('-s', '--space', help='The space name contains.', type=str,
									default="")
	arg_group_criteria.add_argument('-z', '--zone', help='The zone name contains.', type=str,
									default="")

	args = arg_parser.parse_args()
	logger.debug('Arguments ' + str(args))

	main(args)
