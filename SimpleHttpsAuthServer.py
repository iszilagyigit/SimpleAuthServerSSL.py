#
# Python3 script
#
import http.server
import socketserver
from http.server import SimpleHTTPRequestHandler
import sys
import os
import base64
import ssl


key = ""

#
#  key and self signed certificate created with:
#  openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem
#
CERTFILE_PATH = "/home/ubuntu/https/cert.pem"
KEYFILE_PATH= "/home/ubuntu/https/key.pem"

class AuthHandler(SimpleHTTPRequestHandler):
    ''' Main class to present webpages and authentication. '''
    def do_HEAD(self):
        print ("send header")
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_AUTHHEAD(self):
        print ("send header")
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Test\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        global key
        ''' Present frontpage with user authentication. '''
        if self.headers.get('Authorization') == None:
            self.do_AUTHHEAD()
            self.wfile.write('no auth header received'.encode('utf-8'))
            pass
        elif self.headers.get('Authorization') == 'Basic '+str(key,'utf-8'):
            SimpleHTTPRequestHandler.do_GET(self)
            pass
        else:
            self.do_AUTHHEAD()
            self.wfile.write(self.headers.get('Authorization'))
            self.wfile.write('not authenticated'.encode('utf-8'))
            pass

def serve_https(https_port=80, HandlerClass = AuthHandler,
         ServerClass = http.server.HTTPServer):
    httpd = socketserver.TCPServer(("", https_port), HandlerClass)
    httpd.socket = ssl.wrap_socket (httpd.socket, certfile=CERTFILE_PATH, keyfile=KEYFILE_PATH, server_side=True)

    sa = httpd.socket.getsockname()
    print ("Serving HTTP on", sa[0], "port", sa[1], "...")
    httpd.serve_forever()

if __name__ == '__main__':
    if len(sys.argv)<3:
        print ("usage SimpleAuthServer.py [port] [username:password]")
        sys.exit()

    https_port = int(sys.argv[1])
    key = base64.b64encode(sys.argv[2].encode('utf-8'))

    serve_https(https_port)

