# ---------------------------------------------------------------------------------------------
# Title:		    Trellis(tm) Enterprise - Symbol Updater
# Description:      Replace all device symbols with their latest version loaded in Trellis(tm).
# Script Name:      trellis-symbol-update.py
# Created:          2019/11/01
# Modified:         2021/04/29
# Author:           Scott Donaldson [VERTIV/AVOCENT/UK]
# Contributors:
# Company:          Vertiv Infrastructure Ltd.
# Group:            Life-Cycle Engineering, IT Systems
# Email:            global.services.delivery.development@vertivco.com
# License:          BSD-3 Clause (included)
# Instructions:     README.md
# ---------------------------------------------------------------------------------------------

#
# Imports
#
import os
import base64
import http.client
import ssl
import json
import time
import logging
import logging.config
import argparse
import asyncio
import aiohttp
# import aiodns
import sys
import pprint
import requests
import uuid
import defusedxml
# import defusedexpat
# import defusedyaml
from requests import Request, Session, Response
from http import HTTPStatus
from http import cookies
from http import client
from typing import Any

#####

version = '0.3'
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
DEFAULT_PROJECTION = 'summary'
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

'''
API Limits
TODO: Replace these with input values.
'''
DEFAULT_PAGE_SIZE = 100
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

#
# Configuration
#
# TODO: Replace this with configuration file.
debug = True  # Enable console debugging output.
debugVerbosity = 1  # Control verbosity of debugging output.
client_use_async = True  # Use asynchronous calls to server.
client_use_session = True  # Use session cookie to authenticate calls to server.
limit_async = asyncio.Semaphore(20)  # Constraint for concurrent calls when using asynchronous calls to server.
limit_pages = 100  # Limit on total pages to process.
limit_results = 1000  # Limit results per page to request (Trellis 4.0.3+ enforces limit of 1000 results).

# TODO: Replace this with detection of terminal width
columns = 80


def println():
	print("#" * columns)


class MethodType:
	def __init__(self):
		assert isinstance(copy, (bool, None))
		assert isinstance(delete, (bool, None))
		assert isinstance(get, (bool,None))
		assert isinstance(head, (bool, None))
		assert isinstance(link, (bool, None))
		assert isinstance(lock, (bool, None))
		assert isinstance(option, (bool, None))
		assert isinstance(patch, (bool, None))
		assert isinstance(post, (bool, None))
		assert isinstance(propfind,(bool, None))
		assert isinstance(purge, (bool, None))
		assert isinstance(put, (bool, None))
		assert isinstance(trace, (bool, None))
		assert isinstance(unlink, (bool, None))
		assert isinstance(unlock, (bool, None))
		assert isinstance(view, (bool, None))

		self.copy = False
		self.delete = None
		self.get = None
		self.head = True
		self.link = False
		self.lock = False
		self.option = None
		self.patch = None
		self.post = None
		self.propfind = False
		self.purge = False
		self.put = None
		self.trace = False
		self.unlink = False
		self.unlock = False
		self.view = False


class ProjectionType:
	def __init__(self):
		assert isinstance(all, (bool, None))
		assert isinstance(actions, (bool, None))
		assert isinstance(alarmcounts, (bool, None))
		assert isinstance(basic, (bool, None))
		assert isinstance(capacity, (bool, None))
		assert isinstance(details, (bool, None))
		assert isinstance(devices, (bool, None))
		assert isinstance(metrics, (bool, None))
		assert isinstance(monitoring, (bool, None))
		assert isinstance(openings, (bool, None))
		assert isinstance(permissions, (bool, None))
		assert isinstance(placements, (bool, None))
		assert isinstance(roletenancy, (bool, None))
		assert isinstance(search, (bool, None))
		assert isinstance(slots, (bool, None))
		assert isinstance(summary, (bool, None))
		assert isinstance(tenancy, (bool, None))
		assert isinstance(udp, (bool, None))
		assert isinstance(visualization, (bool, None))

		self.all = None
		self.actions = None
		self.alarmcounts = None
		self.basic = None
		self.capacity = None
		self.details = None
		self.devices = None
		self.metrics = None
		self.monitoring = None
		self.openings = None
		self.permissions = None
		self.placements = None
		self.roletenancy = None
		self.search = None
		self.slots = None
		self.summary = None
		self.tenancy = None
		self.udp = None
		self.visualization = None


class ResultsType:
	def __init__(self):
		assert isinstance(self.total_results, int)
		assert isinstance(self.total_pages, int)
		assert isinstance(self.page_size, int)
		assert isinstance(self.valid, bool)
		assert isinstance(self.payload, (json, xml, None))
		self.total_results = None
		self.total_pages = None
		self.page_size = None
		self.valid = False
		self.payload = None


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
	def __init__(self, symbol_id=None):
		assert isinstance(symbol_id, int)
		self.symbol_id = symbol_id
		self.left_child = None
		self.right_child = None


class SymbolBinarySearchTree:
	def __init__(self):
		self.root = None

	def insert(self, symbol_id):
		if self.root is None:
			self.root = NodeType(symbol_id)
			# self.root.symbol = symbol_t(symbol)
		else:
			self._insert(symbol_id, self.root)

	def _insert(self, symbol_id, cur_node):
		if symbol_id < cur_node.symbol_id:
			if cur_node.left_child is None:
				cur_node.left_child = NodeType(symbol_id)
				# cur_node.left_child.symbol = symbol_t(symbol)
			else:
				self._insert(symbol_id, cur_node.left_child)
		elif symbol_id > cur_node.symbol_id:
			if cur_node.right_child is None:
				cur_node.right_child = NodeType(symbol_id)
				# cur_node.right_child.symbol = symbol_t(symbol)
			else:
				self._insert(symbol_id, cur_node.right_child)
		else:
			logger.warning("Value already in tree.")

	def print_tree(self):
		if self.root is not None:
			self._print_tree(self.root)

	def _print_tree(self, cur_node):
		if cur_node is not None:
			self._print_tree(cur_node.left_child)
			print(str(cur_node.symbol_id))
			logger.debug(str(cur_node.symbol_id))
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

	def search_by_id(self, symbol_id: int) -> bool:
		if self.root is not None:
			return self._search_by_id(symbol_id, self.root)
		else:
			return False

	def _search_by_id(self, symbol_id: int, cur_node) -> bool:
		if symbol_id == cur_node.symbol_id:
			return True
		elif symbol_id < cur_node.symbol_id and cur_node.left_child is not None:
			return self._search_by_id(symbol_id, cur_node.left_child)
		elif symbol_id > cur_node.symbol_id and cur_node.right_child is not None:
			return self._search_by_id(symbol_id, cur_node.right_child)
		else:
			return False


class HttpClient:

	def __init__(self, unsafe_https, timeout=300, debug_level=0, mode='sync'):
		"""
		Initialize client instance.
		:param unsafe_https:
			When set the standard certificate & host validations checks are suppressed.
		"""
		self._unsafe_https = unsafe_https
		self._timeout: int = timeout
		self._debug_level = debug_level
		self._mode = mode
		self._conn: (http.client.HTTPSConnection, http.client.HTTPConnection, None) = None
		self._headers_auth = None
		self._headers_session = None
		self._http_ctx = None

		if self._https_protocol_coverage is True:
			self._http_ctx = _http_prepare_context(unsafe_https)
		elif self._http_protocol_coverage is True:
			self._http_ctx = _http_prepare_context(None)
		else:
			logger.fatal("Supported communication protocols undetermined.")

	def sync_connection(self, http_host):
		if self._conn is None:
			self._conn = http.client.HTTPSConnection(http_host, self.http_ctx)
			self._conn.debuglevel = self._debug_level
			self._conn.timeout = self._timeout
			self._mode = 'sync'
			return True
		else:
			logger.warning("Connection already established.")
			return False

	def async_connection(self, http_host) -> http.client.HTTPSConnection:
		if self._conn is None:
			self._conn = http.client.HTTPSConnection(http_host, self.http_ctx)
			self._conn.debuglevel = self._debug_level
			self._conn.timeout = self._timeout
			self._mode = 'async'
		else:
			logger.warning("Connection already established.")

	def get_session(self, http_headers) -> bool:
		# A quick call to API root to generate Session Cookie

		try:
			self._conn.request(method="HEAD", url='/api/rest/v1/', headers=http_headers)
			api_response = self._conn.getresponse()
		except Exception as ex:
			logger.exception("Connection failed.")
			logger.exception(str(ex))
			return False
		finally:
			self._conn.close()

		if (api_response.status != HTTPStatus.OK) and (api_response.status != HTTPStatus.NO_CONTENT):
			logger.error(("Connection Status: %s", str(api_response.status)))
			self._headers_auth = http_headers
			self._headers_session = None
			return False
		elif (api_response.status is HTTPStatus.FORBIDDEN) or (api_response.status is HTTPStatus.UNAUTHORIZED):
			logger.error(("Connection Status: %s", str(api_response.status)))
			logger.error("Please verify authentication credentials.")
			return False
		else:
			logger.info(("Connection Status: %s", str(api_response.status)))
			logger.debug(("Response Headers: %s", json.dumps(http_headers)))
			http_headers.update({'Cookie': api_response.getheader('Set-Cookie')})
			del http_headers['authorization']
			self._headers_session = http_headers
			logger.debug(("Updated Request Headers: " + json.dumps(self._headers_session)))
		return True

	def _http_protocol_coverage() -> (bool, None):
		"""
		TODO: Implement checks for SSLv3, TLSv1, TLSv1.1, TLSv1.2, TLSv1.3
		Verify supported profile and ciphers.

		Parameters
		----------
		method : {'HEAD','GET'}
			HTTP method to use for checks.

		"""
		return True

	def _https_protocol_coverage() -> (bool, None):
		"""
		TODO: Implement checks for SSLv3, TLSv1, TLSv1.1, TLSv1.2, TLSv1.3
		Verify supported profile and ciphers.

		Parameters
		----------
		method : {'HEAD','GET'}
			HTTP method to use for checks.

		"""
		# TODO: Implement correctly as connection is initialized based on these.
		return True

	def _http_prepare_context(self, unsafe_https: bool):
		"""

		:param unsafe_https: bool
			When set it disables the default certificate validations, if None is passed then it will fall back to HTTP.
		:return: ssl.SSLContext
			Returns a configured context for http.client / asyncio.http.
		"""
		#
		# Connection Definitions
		#
		# TODO: Support TLSv1.3, TLSv1.2 instead with clean fallback.
		if unsafe_https is None:
			# TODO: Implement HTTP context.
			print("HTTP fallback is unimplemented.")
		elif unsafe_https is False:
			self.http_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
			# TODO: Consider disabling TLSv1_1 (this will break Trellis 4.x support)
			self.http_ctx.options = ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_SINGLE_DH_USE  # ssl.OP_NO_TLSv1
			self.http_ctx.options &= ssl.VERIFY_CRL_CHECK_CHAIN | ssl.VERIFY_CRL_CHECK_LEAF
			self.http_ctx.options &= ssl.OP_NO_COMPRESSION
			self.http_ctx.options &= ssl.CERT_REQUIRED

			# TODO: Handle JKS/PKCS12 keystore
			# keystore = self.http_ctx.get_cert_store()
			# self.http_ctx.use_privatekey(load_privatekey(FILETYPE_PEM, client_key_pem))
			# self.http_ctx.use_certificate(load_certificate(FILETYPE_PEM, client_cert_pem))
			# self.http_ctx.check_privatekey()
			# keystore.add_cert(load_certificate(FILETYPE_PEM, root_cert_pem))
		else:
			logger.warning("Client connectivity settings are insecure. Please review connectivity settings.")

			# TODO: Pull settings from configuration file.
			# TODO: Document that these are insecure settings as they enable SSL!
			self.http_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
			self.http_ctx.options = ssl.OP_NO_SSLv3 | ssl.OP_SINGLE_DH_USE | ssl.OP_NO_COMPRESSION
			self.http_ctx.check_hostname = False
			self.http_ctx.verify_mode = ssl.CERT_NONE

			# TODO: Handle certificates correctly, with actual trust enforcement.
			# self.http_ctx.verify_mode = ssl.CERT_REQUIRED
			# self.http_ctx.load_verify_locations('./certs/ca-bundle.crt')

	async def _async_get(url, headers, ctx):
		async with aiohttp.ClientSession() as session:
			async with session.get(url, headers=headers, ssl=ctx) as response:
				await response.read()
				print(response)
				logger.debug(response)

	async def _async_post(url, payload, headers, ctx):
		async with aiohttp.ClientSession() as session:
			async with session.post(url, data=payload, headers=headers, ssl=ctx) as response:
				await response.read()
				print(response)
				logger.debug(response)

	async def safe_async_get(url, headers, ctx):
		async with limit_async:
			return await async_get(url=url, headers=headers, ctx=ctx)

	async def safe_async_post(url, payload, headers, ctx):
		async with limit_async:
			return await async_post(url=url, payload=payload, headers=headers, ctx=ctx)

	async def batch_async_get(url, result_pages, session_headers, http_ctx, page_size=100, projection='summary'):
		tasks = [
			asyncio.ensure_future(safe_async_get(
				url=(url + genuri_devices_get_all(page_size, i, projection)),
				headers=session_headers, ctx=http_ctx))
			for i in range(result_pages)
		]
		await asyncio.gather(*tasks)

	def conn() -> (http.client.HTTPSConnection, http.client.HTTPConnection):
		return self._conn


class Symbols:

	def __init__(self, conn: (HttpClient)):
		if isinstance(conn, (HttpClient)):
			self._conn = conn
		else:
			raise TypeError("Invalid type for client.")


	async def batch_async_symbols_get(base_url, result_pages, session_headers, http_ctx, page_size=100,
									  projection='summary'):
		tasks = [
			asyncio.ensure_future(safe_async_get(
				url=(base_url + genuri_symbols_get_all(page_size, i, projection)),
				headers=session_headers,
				ctx=http_ctx))
			for i in range(result_pages)
		]
		await asyncio.gather(*tasks)

	def sync_getall_symbols_pages(conn: http.client.HTTPSConnection, http_headers, call_method: {"GET", "HEAD"},
								  api_pagesize, api_pagenum,
								  api_projection: {'all', 'basic', 'summary'}) -> ResultsType:
		"""
		Query the number of results that would be returned by the operation.

		Parameters
		----------
		ctx : ssl.SSLContext
			HTTP method to use for checks.
			:param conn:
			:param http_headers:
			:param call_method:
			:param api_pagenum:
			:param api_pagesize:
			:param api_projection:
			:return:

		"""
		ret = ResultsType

		try:
			conn.request(call_method, url=genuri_symbols_get_all(api_pagesize, api_pagenum, api_projection),
						 headers=http_headers)
		except Exception as e:
			logger.exception("Connection failure.")
			logger.exception(str(e))

		try:
			res = conn.getresponse()
			if res.status != HTTPStatus.OK:
				logger.error("Status ", res.status)
				return ret
			json_response = json.loads(res.read(), encoding='utf-8')
		except Exception as e:
			logger.exception("Response failure.")
			logger.exception(str(e))
			return ret

		ret.total_pages = int(json_response['page']['totalPages'])
		ret.page_size = api_pagesize
		ret.total_results = int(json_response['page']['totalElements'])
		# TODO: Add validation for JSON payload.
		ret.valid = True
		return ret

	def uri_get_all(page_size, page_num, projection: {"all", "summary", "basic"}) -> str:
		"""
			Prepares API path for all symbols call.

			Parameters
			----------
			pageSize : int
			pageNum :  int
			:param pageSize:
			:param pageNum:
			:param resultProjection:
			:return:

			"""
		api_path = '/api/rest/v1/symbols/'
		if (limit_results >= page_size > 0) and page_num >= 0:
			api_path = api_path + '?size=' + str(page_size) + '&page=' + str(page_num)
		else:
			api_path = api_path + '?size=20&page=0'

		api_path = api_path + "&projection=" + projection
		return api_path


class Devices:

	def __init__(self, conn: (HttpClient)):
		if isinstance(conn, (HttpClient)):
			self._conn = conn
		else:
			raise TypeError("Invalid type for client.")

	def connect(self, host_name: str):
		self._conn._http_prepare_context(True)

	# TODO: Handle wider range of projections for 5.0.x
	def uri_get_all(self, page_num) -> str:
		"""
		Prepares API path for all devices call.

		Parameters
		----------
		pageSize : int
		pageNum :  int
		:param page_size:
		:param page_num:
		:param projection:
		:return:

		"""
		api_path = '/api/rest/v1/devices/'
		if (1000 > self.api_pagesize > 0) and page_num >= 0:
			api_path = api_path + '?size=' + str(self.api_pagesize) + '&page=' + str(page_num)
		else:
			api_path = api_path + '?size=20&page=0'

		api_path = api_path + "&projection=" + self.api_projection
		return api_path

	def sync_get_all(conn: http.client.HTTPSConnection, http_headers, api_pagenum: int, api_pagesize: int,
					 api_projection: {"all", "summary", "basic"}) -> json:
		"""
		Query the number of results that would be returned

		Parameters
		----------
		ctx : ssl.SSLContext
			HTTP method to use for checks.
			:param conn:
			:param http_ctx:
			:param api_pagenum:
			:param api_pagesize:
			:param api_projection:
			:return:

		"""
		try:
			start_time: float = time.perf_counter()
			conn.request(method="GET", url=genuri_devices_get_all(api_pagesize, api_pagenum, api_projection),
						 headers=http_headers)
			elapsed_time: float = time.perf_counter() - start_time
			print(f"\tConnection Request -\t{elapsed_time:12.6f}s")
		except Exception as e:
			logger.error("Connection failure.")
			logger.error(str(e))

		try:
			start_time: float = time.perf_counter()
			res = conn.getresponse()
			elapsed_time: float = time.perf_counter() - start_time
			print(f"\tFetch Response -\t\t{elapsed_time:12.6f}s")
			if res.status != HTTPStatus.OK:
				logger.error("Status ", res.status)
				return -1
			json_response = json.loads(res.read(), encoding='utf-8')
		except Exception as e:
			logger.error("Response failure.")
			logger.error(str(e))
			return -1
		# TODO: Extract results & pages from payload and return

		return json_response

	def sync_getalldevices_results(conn: http.client.HTTPSConnection, http_headers,
								   call_method: {"GET", "HEAD"}) -> int:
		"""
		Query the number of results that would be returned

		Parameters
		----------
		call_method : {'HEAD','GET'}
			HTTP method to use for checks.
			:param conn:
			:param call_method:
			:param http_ctx:
			:param http_headers:
			:return:

		"""

		if call_method == 'HEAD':
			try:
				conn.request(method="HEAD", url=genuri_devices_get_all(10, 0), headers=http_headers)
				res = conn.getresponse()
				data = res.read()
				# TODO: Update once API returns correct 204 instead of 200 on HEAD
				if res.status != HTTPStatus.NO_CONTENT or res.status != HTTPStatus.OK:
					logger.error("Status ", res.status)
					return -1
			except Exception as e:
				logger.error("Request failure.")
				logger.error(e)
				return -1
			# TODO: Extract results & pages from header and return
		else:

			try:
				conn.request(method="GET", url=genuri_devices_get_all(10, 0, resultProjection="basic"),
							 headers=http_headers)
			except Exception as e:
				logger.critical("Connection failure.")
				logger.critical(str(e))

			try:
				res = conn.getresponse()
				json_response = json.loads(res.read(), encoding='utf=8')
				logger.debug(json_response)
				if res.status != HTTPStatus.OK:
					logger.error("Status ", res.status)
					return -1
			except Exception as e:
				logger.error("Response failure.")
				logger.error(str(e))
				return -1
			# TODO: Extract results & pages from payload and return

		logger.info("totalPages - " + str(json_response['page']['totalPages']) + " totalElements - " + str(
			json_response['page']['totalElements']))

		return int(json_response['page']['totalPages'])


# TODO: Unimplemented, it needs to be implemented.
class SymbolTree:
	def fill_symbol_tree(tree, http_ctx, headers, symbol_pages):
		# TODO: Implement fetches to symbol catalog
		test_symbol = SymbolType
		test_symbol_id = uuid.UUID('cc960f28-bdd2-4429-a134-b7e3a90349f8').int

		tree.insert(test_symbol_id)
		# tree.insert(uuid.UUID('cc960f28-bdd2-4429-a134-b7e3a90349f8').int)
		tree.insert(uuid.UUID('8c75122f-32af-4077-b16d-619145e32e5c').int)

		loop = asyncio.get_event_loop()
		try:
			loop.run_until_complete(batch_async_symbols_get(base_url='https://trellis-front',
															result_pages=symbol_pages,
															session_headers=headers,
															http_ctx=http_ctx,
															page_size=1000,
															projection="summary"))
		finally:
			loop.run_until_complete(loop.shutdown_asyncgens())
			loop.close()



	def symbol_tree_add():
		return ''


	def symbol_tree_search():
		return ''


	def symbol_query_newest():
		"""
		TODO: Query the latest version

		"""
		return ''



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
		'days': DEFAULT_MATCH_DAYS
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
		# TODO: Port to newer class.
		#session.verify = False
	#else:
		# TODO: Port to newer class.
		#session.verify = True

	if (0 < arguments.set_pagesize < SANITIZE_MAX_PAGE_SIZE):
		api_pagesize = arguments.set_pagesize
	else:
		api_pagesize = DEFAULT_PAGE_SIZE  # type: int

	#
	#  Prepare Connection Headers
	#
	trellis_user_auth = base64.urlsafe_b64encode(bytes((_username + ':' + _password), "utf-8"))
	http_headers = DEFAULT_REQUEST_HEADERS
	http_headers.update({
		'authorization': 'Basic %s' % trellis_user_auth.decode("utf-8", "ignore")
	})
	#####

	#
	#  Prepare API Calls
	#
	api_projection = DEFAULT_PROJECTION

	http_client = HttpClient(unsafe_https = True)

	print(str(http_client))
	print("api_pagesize: " + str(api_pagesize))
	print("api_projection: " + str(api_projection))
	print("http_headers: " + str(http_headers))
	device_context = Devices(http_client)
	print("device_context: ")
	print(device_context)
	print("Connecting to " + _hostname)
	device_context.connect(_hostname)
	#initialized_conn = sync_connection(http_hostfqdn, http_ctx)
	device_pages = -1  # type: int

	# Fetch symbol count using GET (currently HEAD does not enumerate results correctly for 5.0.x)
	# TODO: Implement OPTIONS check & HEAD check to support results in HEAD reponse headers.
	symbol_pages = -1  # type: int
	logger.info("Processing symbols catalogue.")
	symbol_results = ResultsType
	try:
		symbol_results = sync_getall_symbols_pages(initialized_conn, http_headers, call_method='GET',
																api_pagesize=limit_results, api_projection='summary',
																api_pagenum=0)
		symbol_pages = symbol_results.total_pages
		logger.info("Connection succeeded.")
	except():
		symbol_pages = 0
		logger.error("Connection failed.")
	finally:
		logger.info("Total symbol: %s \t Total pages: %s \tResults per page: %s", str(symbol_results.total_results),
					str(symbol_results.total_pages), str(symbol_results.page_size))

	symbol_tree = None
	if symbol_results.total_results > 0:
		symbol_tree = SymbolBinarySearchTree()
		fill_symbol_tree(symbol_tree, 1000, initialized_conn, session_headers)
		logger.info("Symbol tree height is %s", int(symbol_tree.height()))
		if symbol_tree.height() <= 0 or symbol_tree.height() is None:
			logger.error("Unable to populate symbol tree.")
			return sys.exit(-1)
	else:
		logger.error("Unable to populate symbol tree.")
		return sys.exit(-1)

	# symbol_tree.print_tree()

	if device_pages > 0:

		# Place upper limit on results to process.
		if device_pages > limit_pages:
			logger.warning(("Total devices %s exceed defined limit of %s.", str(device_pages), str(limit_pages)))
			device_pages = limit_pages

		# Process synchronously or async?
		if not client_use_async:

			start_process_time: float = time.process_time()
			start_real_time: float = time.perf_counter()
			for api_pagenum in range(0, device_pages):
				print("Fetching page " + str(api_pagenum) + " of " + str(device_pages))
				logger.info("Fetching page " + str(api_pagenum) + " of " + str(device_pages))

				page_resp = sync_getalldevices(initialized_conn, session_headers, api_pagenum, api_pagesize,
											   api_projection)

				logger.info("Response size - " + str(json.dumps(page_resp).__sizeof__()) + " bytes")
				if debug and debugVerbosity > 2:
					logger.debug(json.dumps(page_resp))
			#####
			elapsed_process_time: float = time.process_time() - start_process_time
			elapsed_real_time: float = time.perf_counter() - start_real_time

			# TODO: Output to results file.
			print(f"\tTotal Real Time \t-\t\t{elapsed_real_time:12.6f}s")
			print(f"\tTotal Processing Time -\t\t{elapsed_process_time:12.6f}s")

		else:
			start_process_time: float = time.process_time()
			start_real_time: float = time.perf_counter()

			loop = asyncio.get_event_loop()
			try:
				loop.run_until_complete(batch_async_get(device_pages, session_headers, http_ctx))
			finally:
				loop.run_until_complete(loop.shutdown_asyncgens())
				loop.close()

			elapsed_process_time: float = time.process_time() - start_process_time
			elapsed_real_time: float = time.perf_counter() - start_real_time

			# TODO: Output to results file.
			print(f"\tTotal Real Time \t-\t\t{elapsed_real_time:12.6f}s")
			print(f"\tTotal Processing Time -\t\t{elapsed_process_time:12.6f}s")
	else:
		logger.error("No results to process.")
	#
	#
	#
	logger.info("Complete.")


#####


if __name__ == '__main__':

	if sys.version_info[0] < 3:
		raise Exception("Error: Python 3.0+ is required.")

	##
	#  Setup Logging
	#
	if os.path.exists('./logging.conf'):
		logging.config.fileConfig('./logging.conf')
	else:
		# Default to RFC2822 standard
		logging.basicConfig(filename='trellis-symbol-update.log', filemode='w',
							level=logging.WARNING,
							format='%(module)s (%(process)s) %(levelname)s %(asctime)s %(message)s',
							datefmt='%Y%m%d-%H:%M:%S%z')
	logger = logging.getLogger(__name__)
	logger.setLevel(logging.DEBUG)

	logger.info("Logging started.")
	#####

	##
	#  Configuration
	#
	logger.info('Processing arguments.')
	argParser = argparse.ArgumentParser(description="Vertiv™ Trellis™ Enterprise - Symbol Updater")
	argGroupMethod = argParser.add_mutually_exclusive_group()
	argGroupMethod.add_argument('--sync', help='Use synchronous API calls.')
	argGroupMethod.add_argument('--async', help='Use asynchronous API calls.')
	argParser.add_argument('--insecure', help='Disable HTTPS validations.')
	argParser.add_argument('-d', '--debug', help='Enable debug output.', type=str, choices=['true', 'false'])
	argParser.add_argument('-t', '--host', help='Trellis(tm) hostname.', type=str, default=DEFAULT_TRELLIS_HOST)
	argParser.add_argument('-p', '--protocol', help='Protocol HTTP|HTTPS', type=str, choices=['http', 'https'], 
						default=DEFAULT_CONN_PROTO)
	argParser.add_argument('-P', '--port', help='TCP port', type=int, default=DEFAULT_CONN_PORT)
	argParser.add_argument('-u', '--user', help='Authenticating user name.', type=str, default=DEFAULT_TRELLIS_USER)
	argParser.add_argument('-a', '--password', help='Authenticating user password (not recommended to pass as parameter).', type=str, default=None)
	argParser.add_argument('-v', '--verbose', help='Displays script version information.')
	argParser.add_argument('-C', '--config', help='Specify configuration file.')
	argParser.add_argument('-o', '--output-responses', help='Specify response output file.')
	argParser.add_argument('-O', '--output-metrics', help='Specify metrics output file.')

	argGroupApi = argParser.add_argument_group()
	argGroupApi.add_argument('--set-pagesize', help='Set results per response page.', type=int, default=100)
	argGroupApi.add_argument('--set-pagelimit', help='Set limit on number of pages to process.', type=int, default=None)
	argGroupApi.add_argument('--set-projection', help='Set level of detaul for response (projection).', type=str,
							 choices=['summary', 'all', 'basic'], default="summary")

	argGroupCriteria = argParser.add_argument_group()
	argGroupCriteria.add_argument('-b', '--building', help='The building name contains.', type=str,
									default=None)
	argGroupCriteria.add_argument('-f', '--floor', help='The floor name contains.', type=str,
									default=None)
	argGroupCriteria.add_argument('-s', '--space', help='The space name contains.', type=str,
									default=None)
	argGroupCriteria.add_argument('-z', '--zone', help='The zone name contains.', type=str,
									default=None)
	argGroupCriteria.add_argument('-T', '--typeidentifier', help='The typeIdentifier name is.', type=str,
									default=None)
	args = argParser.parse_args()
	logger.debug('Arguments ' + str(args))
	#####

	println()
	print('\n  Vertiv™ Trellis™ Enterprise - Symbol Updater (v' + version + ')\n\n')
	try:
		main(args)
	except (KeyboardInterrupt, SystemExit):
		print('\nUser aborted operation.\n')
		logger.error('User aborted operation.')
		raise
	finally:
		println()
