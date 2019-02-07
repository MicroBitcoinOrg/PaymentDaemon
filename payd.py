# Copyright (c) 2019 iamstenman
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#!/usr/bin/env python3
"""
Usage::
	./payd.py [<port>]
"""
from core.wallet import Key
from core.format import to_satoshis, key_to_pub, bytes_to_wif, public_key_to_address, is_float
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse
from rpc import Rpc
import hashlib
import json

class Seed():
	def __init__(self, data, iterations):
		self.data = data
		self.iterations = iterations

	def seed_key(self, raw_data, iterations):
		data = hashlib.sha256(raw_data.encode())
		while iterations > 0:
			data = hashlib.sha256(data.digest())
			iterations -= 1

		return data.digest()

	def new(self):
		privkey = self.seed_key(self.data, self.iterations)
		pubkey = key_to_pub(privkey)
		return {
			"wif": bytes_to_wif(privkey),
			"address": public_key_to_address(pubkey)
		}

class RpcServer(BaseHTTPRequestHandler):
	def _set_response(self):
		self.send_response(200)
		self.send_header('Content-type', 'application/json')
		self.send_header('Access-Control-Allow-Origin', '*')
		self.end_headers()

	def handle_request(self, data):
		response = Rpc().dead()
		if "error" not in data:
			if data["method"] == "blockchain.address.bake":
				if len(data["params"]) == 2 and data["params"][1].isnumeric():
					response = Rpc().create(Seed(data["params"][0], int(data["params"][1])).new(), data["id"])

			elif data["method"] == "blockchain.transaction.create":
				if len(data["params"]) >= 3 and len(data["params"][0]) in (51, 52) and len(data["params"][1]) == 34 and is_float(data["params"][2]):
					outputs = [(data["params"][1], float(data["params"][2]))]
					tx_fee = to_satoshis(float(data["params"][3])) if len(data["params"]) == 4 and is_float(data["params"][3]) else 1000
					result = {}

					try:
						key = Key(data["params"][0])
					except Exception as e:
						result["error"] = str(e)

					if "error" not in result:
						try:
							result = key.new_tx(outputs, fee=tx_fee, absolute_fee=True)
						except Exception as e:
							result["error"] = str(e)

					response = Rpc().create(result, data["id"])

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
