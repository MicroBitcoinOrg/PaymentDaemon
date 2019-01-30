import re
import json
from urllib import parse

node_name = 'PaymenDaemon'
allowed = [
	"blockchain.address.bake",
	"blockchain.transaction.create"
]

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