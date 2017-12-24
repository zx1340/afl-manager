import os,sys
import argparse
import glob
import BaseHTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
import datetime
import base64
import requests
from afl import Afl
from utils import *
from data import *

HOST_NAME = '0.0.0.0'
PORT_NUMBER = 1340

#Simple Http server reponse get
class MyHandler(SimpleHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
    
    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Test\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        """Respond to a GET request."""
        #authencation check
        if self.headers.getheader('Authorization') == None:
            self.do_AUTHHEAD()
            self.wfile.write('no auth header received')
            return
        
        elif self.headers.getheader('Authorization') == 'Basic '+key:
            #SimpleHTTPRequestHandler.do_GET(s)
            #pass
            if self.path.endswith(".css"):
                f = open(self.path[1:])
                self.send_response(200)
                self.send_header('Content-type', 'text/css')
                self.end_headers()
                self.wfile.write(f.read())
                f.close()
                return

            if self.path == '/crashes':
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(all_crash_start)

                self.wfile.write('<h1 onclick="window.history.go(-1); return false;">' + 'HOME' + '</h1>')

                for afl in lafl:
                    self.wfile.write(afl.get_crash_info())
                self.wfile.write(web_end)
                return

            if self.path.endswith('.info'):
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                try:
                    fz_dir = int(self.path[1:-5])
                except:
                    self.wfile.write("<h1>There is nothing here</h1>")
                    return

                self.wfile.write(crash_start)
                for afl in lafl:
                    if fz_dir == afl.fuzzer_pid:
                        self.wfile.write('<h1 onclick="window.history.go(-1); return false;">' + os.path.abspath(afl.path) + '</h1>')
                        self.wfile.write(afl.get_full_crash_info())
                        self.wfile.write(web_end)
                        self.wfile.write(finfo_start)
                        self.wfile.write(afl.get_queue())
                        self.wfile.write(finfo_end)
                        return
                self.wfile.write("<h1>There is nothing here</h1>")
                return
        
        else:
            self.do_AUTHHEAD()
            self.wfile.write(self.headers.getheader('Authorization'))
            self.wfile.write('not authenticated')
            return

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(web_start)
        
        for afl in lafl:
            self.wfile.write(afl.get_build_info())
        self.wfile.write(web_end)


#need parent folder of afl output folder
#-b is option using asan to recheck crash
parser = argparse.ArgumentParser(description='AFL Manager')
parser.add_argument('-i', action="store", dest="source", required=True, help='Parent directory of AFL')
parser.add_argument('-b', action="store", dest="binary", required=False,help="binary ")
parser.add_argument('-a', action="store", dest="authen", required=True,help="Authencation user:pass")
args = parser.parse_args()

source = args.source
cmd = args.binary if args.binary else None

key = base64.b64encode(args.authen)

if not cmd:
    print("[*]No input binary, using afl info at default")
else:
    if not os.path.exists(cmd):
        print("[-]Oops, binary seem not exists (%s)\ncheck pls",cmd)
        sys.exit()

lafl = []

print "[+]Getting crash info...."
if os.path.exists(source):
    afl_instance = get_afl_instance(source)
    if not len(afl_instance):
        print("[-]Oops, afl root folder seem not exists (%s)\ncheck pls",source)
        sys.exit()

    for afl in afl_instance:
        lafl.append(Afl(afl,cmd))

#Start server
server_class = BaseHTTPServer.HTTPServer
httpd = server_class((HOST_NAME, PORT_NUMBER), MyHandler)
print time.asctime(), "Server Starts - %s:%s" % (HOST_NAME, PORT_NUMBER)
try:
    httpd.serve_forever()
except KeyboardInterrupt:
    pass
httpd.server_close()
print time.asctime(), "Server Stops - %s:%s" % (HOST_NAME, PORT_NUMBER)


