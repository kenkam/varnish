#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler,HTTPServer
import argparse, os, sys, requests, jwt

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
            url = 'http://{}{}'.format(context['hostname'], self.path)

            token = self._get_authorization_token(self.headers)
            if not is_valid_jwt(token):
                self.send_error(401, 'invalid jwt')
                sent = True
                return

            resp = requests.get(url, headers=self.headers, verify=False)
            sent = True

            self.send_response(resp.status_code)
            self.send_resp_headers(resp)
            msg = resp.text
            if body:
                self.wfile.write(msg.encode(encoding='UTF-8',errors='strict'))
            return
        finally:
            if not sent:
                self.send_error(500, 'error trying to proxy')

    # def parse_headers(self):
    #     req_header = {}
    #     for line in self.headers:
    #         line_parts = [o.strip() for o in line.split(':', 1)]
    #         if len(line_parts) == 2:
    #             req_header[line_parts[0]] = line_parts[1]
    #     return req_header

    def send_resp_headers(self, resp):
        respheaders = resp.headers
        for key in respheaders:
            if key not in ['Content-Encoding', 'Transfer-Encoding', 'content-encoding', 'transfer-encoding', 'content-length', 'Content-Length']:
                self.send_header(key, respheaders[key])
        self.send_header('Content-Length', len(resp.content))
        self.end_headers()

    def _get_authorization_token(self, headers):
        authorization = headers.get('Authorization', '')
        prefix = 'Bearer '
        if not authorization.startswith(prefix):
            return ''
        token = authorization[len(prefix):]
        return token

def parse_args(argv=sys.argv[1:]):
    parser = argparse.ArgumentParser(description='Proxy HTTP requests')
    parser.add_argument('--port', dest='port', type=int, default=8080,
                        help='serve HTTP requests on specified port (default: 8080)')
    parser.add_argument('--hostname', dest='hostname', type=str, help='hostname to be processd')
    parser.add_argument('--authority', dest='authority', type=str, help='OIDC authority')
    args = parser.parse_args(argv)
    return args


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


def is_valid_jwt(token):
    #TODO Cache signing key
    jwks_url = f"{context['authority']}/.well-known/openid-configuration/jwks"
    jwks_client = jwt.PyJWKClient(jwks_url)

    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        data = jwt.decode(token, signing_key.key, algorithms=['RS256'], audience='cache')
        return True
    except Exception as e:
        print(f'Failed to decode token: {token}. Error was {e}')
        return False


def main(argv=sys.argv[1:]):
    args = parse_args(argv)
    global context
    context = {}
    context['hostname'] = args.hostname
    context['authority'] = args.authority
    if (args.hostname is None or args.authority is None):
        print('usage: ./main.py --hostname <hostname> --authority <authority> [--port]')
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
