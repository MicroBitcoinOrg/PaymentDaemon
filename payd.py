# Copyright (c) 2018 iamstenman
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#!/usr/bin/env python3
"""
Usage::
	./payd.py [<port>]
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse
import hashlib
import binascii
import base58
import ecdsa
import json
import re

node_name = 'PaymenDaemon'
allowed = [
	"blockchain.address.bake"
]

class Address():
	def hash160(self, raw_hex):
		sha = hashlib.sha256()
		rip = hashlib.new('ripemd160')
		sha.update(raw_hex)
		rip.update(sha.digest())
		return rip.hexdigest()

	def sha256n(self, raw_data, iterations=2):
		data = hashlib.sha256(raw_data.encode()).hexdigest()
		while iterations > 1:
			data = hashlib.sha256(binascii.unhexlify(data)).hexdigest()
			iterations -= 1

		return hashlib.sha256(binascii.unhexlify(data)).hexdigest()

	def uncompressed_to_compressed(self, raw_pubkey):
		order = ecdsa.SECP256k1.generator.order()
		p = ecdsa.VerifyingKey.from_string(raw_pubkey, curve=ecdsa.SECP256k1).pubkey.point
		x_str = ecdsa.util.number_to_string(p.x(), order)
		compressed = bytes(chr(2 + (p.y() & 1)), 'ascii') + x_str
		return compressed

	def secret_to_pubkey(self, secret):
		private_key = ecdsa.SigningKey.from_string(binascii.unhexlify(secret), curve=ecdsa.SECP256k1)
		public_key = private_key.get_verifying_key()
		K = public_key.to_string()
		return K

	def new(self, data, iterations=1):
		privkey = self.sha256n(data, iterations)
		pubkey = self.uncompressed_to_compressed(self.secret_to_pubkey(privkey))
		key = '80' + privkey + '01'
		key_hash = self.sha256n(key)
		addr_hash = '1A' + self.hash160(pubkey)
		checksum = self.sha256n(addr_hash)
		return {
			"wif": base58.b58encode(bytes(bytearray.fromhex(key + key_hash[:8]))).decode('utf-8'),
			"address": base58.b58encode(bytes(bytearray.fromhex(addr_hash + checksum[:8]))).decode('utf-8')
		}

class Rpc():
	def dead(self, code=-32600, message="Invalid Request", rid=node_name):
		return {"jsonrpc": "2.0", "error": {"code": code, "message": message}, "id": rid}

	def handle(self, raw_data):
		result = {
			"jsonrpc": "2.0",
			"params": [],
			"id": node_name
		}

		error = False
		blank = False
		error_message = ""
		error_code = 0
		isjson = False
		method = ""
		rid = ""

		try:
			try:
				data = json.loads(raw_data)
				isjson = True
			except Exception as e:
				data = parse.parse_qs(raw_data)
				print(e)

			if isjson and data["jsonrpc"] != "2.0":
				error = True
				error_message = "Invalid Request"
				error_code = -32600

			if "method" not in data:
				blank = True
			else:
				method = data["method"] if isjson else data["method"][0]
				if method not in allowed:
					error = True
					error_message = "Invalid Request"
					error_code = -32601

			if "params[]" in data:
				data["params"] = data["params[]"]
				data.pop("params[]", None)

			if "id" in data:
				rid = data["id"] if isjson else data["id"][0]
				if type(rid) is str or type(rid) is int:
					result["id"] = rid

			if error is True:
				result["error"] = {
					"code": error_code,
					"message": error_message
				}
			else:
				if blank:
					result["method"] = "server.status"
				else:
					result["method"] = method
					if "params" in data:
						result["params"] = data["params"]

		except ValueError:
			result = self.dead(-32700, "Parse error")

		return result

	def create(self, result_data, rpc_id):
		result = {
			"jsonrpc": "2.0",
			"id": rpc_id
		}

		error = False
		error_message = ""
		error_code = 0

		try:
			if type(result_data) == list or type(result_data) == dict or len(re.findall(r'^[a-fA-F0-9]+$', result_data)) > 0:
				data = result_data

			else:
				error = True
				error_message = "Invalid Request: {}".format(result_data)
				error_code = -32600

			if error is True:
				result["error"] = {
					"code": error_code,
					"message": error_message
				}
			else:
				result["result"] = data
		except Exception as e:
			result = self.dead(-32700, "Parse error")
			print(e)

		return result

class RpcServer(BaseHTTPRequestHandler):
	def _set_response(self):
		self.send_response(200)
		self.send_header('Content-type', 'application/json')
		self.send_header('Access-Control-Allow-Origin', '*')
		self.end_headers()

	def handle_request(self, data):
		response = Rpc().dead()
		if "error" not in data:
			if data["method"] == "blockchain.address.bake" and len(data["params"]) == 2 and data["params"][1].isnumeric():
				response = Rpc().create(Address().new(data["params"][0], int(data["params"][1])), data["id"])

		return response

	def do_GET(self):
		data = Rpc().handle(parse.urlparse(self.path).query)
		response = self.handle_request(data)
		self._set_response()
		self.wfile.write(json.dumps(response, indent=4, sort_keys=True).encode('utf-8'))

	def do_POST(self):
		content_length = int(self.headers['Content-Length'])
		post_data = self.rfile.read(content_length)
		data = Rpc().handle(post_data.decode('utf-8'))
		response = self.handle_request(data)
		self._set_response()
		self.wfile.write(json.dumps(response, indent=4, sort_keys=True).encode('utf-8'))

def run(server_class=HTTPServer, handler_class=RpcServer, port=8000):
	server_address = ('', port)
	payd = server_class(server_address, handler_class)
	print('Starting payd on port {}...\n'.format(port))

	try:
		payd.serve_forever()
	except KeyboardInterrupt:
		pass

	payd.server_close()
	print('Stopping payd...\n')

if __name__ == '__main__':
	from sys import argv

	if len(argv) == 2:
		run(port=int(argv[1]))
	else:
		run()
