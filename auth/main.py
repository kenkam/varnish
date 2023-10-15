#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler,HTTPServer
import argparse, os, sys, requests

from socketserver import ThreadingMixIn
import threading


class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    def do_HEAD(self):
        self.do_GET(body=False)
        return
        
    def do_GET(self, body=True):
        sent = False
        try:
            url = 'http://{}{}'.format(hostname, self.path)
            req_header = self.parse_headers()

            resp = requests.get(url, headers=self.parse_headers(), verify=False)
            sent = True

            self.send_response(resp.status_code)
            self.send_resp_headers(resp)
            msg = resp.text
            if body:
                self.wfile.write(msg.encode(encoding='UTF-8',errors='strict'))
            return
        finally:
            if not sent:
                self.send_error(404, 'error trying to proxy')

    def parse_headers(self):
        req_header = {}
        for line in self.headers:
            line_parts = [o.strip() for o in line.split(':', 1)]
            if len(line_parts) == 2:
                req_header[line_parts[0]] = line_parts[1]
        return req_header

    def send_resp_headers(self, resp):
        respheaders = resp.headers
        for key in respheaders:
            if key not in ['Content-Encoding', 'Transfer-Encoding', 'content-encoding', 'transfer-encoding', 'content-length', 'Content-Length']:
                self.send_header(key, respheaders[key])
        self.send_header('Content-Length', len(resp.content))
        self.end_headers()

def parse_args(argv=sys.argv[1:]):
    parser = argparse.ArgumentParser(description='Proxy HTTP requests')
    parser.add_argument('--port', dest='port', type=int, default=8080,
                        help='serve HTTP requests on specified port (default: 8080)')
    parser.add_argument('--hostname', dest='hostname', type=str, help='hostname to be processd')
    args = parser.parse_args(argv)
    return args

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def main(argv=sys.argv[1:]):
    args = parse_args(argv)
    global hostname
    hostname = args.hostname
    if (hostname is None):
        print('usage: ./main.py --hostname <hostname> [--port]')
        sys.exit(-1)

    print('http server is proxying on {} on :{}...'.format(args.hostname, args.port))
    server_address = ('0.0.0.0', args.port)
    httpd = ThreadedHTTPServer(server_address, ProxyHTTPRequestHandler)
    print('http server is running as reverse proxy')

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('Stopping')
        httpd.server_close()


if __name__ == '__main__':
    main()
