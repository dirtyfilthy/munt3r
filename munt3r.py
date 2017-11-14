#!/usr/bin/python3

import asyncio
import websockets
from aiohttp import web
import argparse
import sys

DEFAULT_PORT=9090

url     = None
cookie  = None
host    = None
port    = DEFAULT_PORT
verbose = False
topic   = None


def verbose_msg(msg):
	global verbose
	if not verbose:
		return
	print(msg)
	sys.stdout.flush()


def as_bytes(v):
	if isinstance(v, bytes):
		return v
	if isinstance(v, str):
		return bytes(v.encode())
	return bytes(v)


def build_request(method, headers, body):
	req = bytearray()
	req.extend("{}\n".format(method).encode())
	for k, v in headers.items():
		req.extend(as_bytes("{}:{}\n".format(k, v)))
	req.append(0x0a)
	req.extend(as_bytes(body))
	req.append(0x00)
	return bytes(req)


def parse_body(raw_resp):
	body_start = raw_resp.find("\n\n")+2
	body_end   = raw_resp.find("{}".format(chr(0)))
	body = raw_resp[body_start:body_end]
	return body


@asyncio.coroutine
def send_request(websocket, method, headers={}, body="", expect_response=False, raw_body=False):
	req = build_request(method, headers, body)
	yield from websocket.send(req)
	if expect_response:
		resp = yield from websocket.recv()
		if  not raw_body:
			resp = parse_body(resp)
		return resp
	return

@asyncio.coroutine
def subscribe(websocket, subid, topic):
	verbose_msg("subscribing to {}..".format(topic))
	yield from send_request(websocket, "SUBSCRIBE", headers={"id":subid,"destination":topic})
	return

@asyncio.coroutine
def disconnect(websocket):
	verbose_msg("disconnect")
	yield from send_request(websocket, "DISCONNECT")
	websocket.close()



@asyncio.coroutine
def connect(url, cookie):
	global host
	global topic
	headers = {}
	if cookie is not None:
		headers["Cookie"] = cookie
	if host is not None:
		headers["Host"] = host
	#headers["X-Application-Context"]="application:uat"
	ws = yield from websockets.connect(url, extra_headers=headers, compression=None)
	verbose_msg("sending CONNECT")
	yield from send_request(ws, "CONNECT", {"accept-version":"1.1,1.2","heart-beat":"0,0"},expect_response=True)
	
	if topic:
		yield from subscribe(ws, subid="sub0", topic=topic)
	verbose_msg("OK")
	return ws

@asyncio.coroutine
def request(url, cookie, dest, body):
	verbose_msg("connecting to {}".format(url))
	ws = yield from connect(url, cookie)

	verbose_msg("sending main...")
	resp = yield from send_request(ws, "SEND", {"destination":dest, "content-length":len(body)}, body, expect_response=True)
	yield from disconnect(ws)
	return resp


@asyncio.coroutine
def handler(req):
	global url
	global cookie
	path = req.path
	data = yield from req.read()
	print("handling request {}".format(path))
	resp = yield from request(url, cookie, path, data)

	return web.Response(body=resp, content_type="text/json")

@asyncio.coroutine
def main_loop(loop):
	global port
	server = web.Server(handler)
	print("spawning server on 127.0.0.1:{}".format(port))
	yield from loop.create_server(server, "127.0.0.1", port)
	yield from asyncio.sleep(100*3600)

def start():
	verbose_msg("started verbose")
	loop = asyncio.get_event_loop()
	try:
		loop.run_until_complete(main_loop(loop))
	except KeyboardInterrupt:
		raise
	loop.close()

def parse_args():
	global cookie
	global host
	global verbose_msg
	global url
	global topic
	parser = argparse.ArgumentParser(description="HTTP to STOMP-over-websocket shim, 2017 Caleb Anderson")
	parser.add_argument('url', metavar='URL', type=str, nargs=1, help='web socket URL for initial handshake i.e. ws://server:1234/socket')
	parser.add_argument("--port","-p", dest="port", type=int, default=DEFAULT_PORT, help="start webserver on port (default {})".format(DEFAULT_PORT))
	parser.add_argument("--cookie","-c", dest="cookie", type=str, default=None, help="cookie for initial websocket handshake")
	parser.add_argument("--host","-H", dest="host", type=str, default=None, help="vhost for Host header")
	parser.add_argument("--subscribe","-s", dest="sub", type=str, default=None, help="subscribe to topic on connect")
	parser.add_argument("--verbose","-v", action="store_true")
	args = parser.parse_args()
	cookie  = args.cookie
	port    = args.port
	url     = args.url[0]
	verbose = args.verbose
	host    = args.host
	topic   = args.sub
	start()

if __name__=="__main__":
	parse_args()






