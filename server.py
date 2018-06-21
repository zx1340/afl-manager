import os,sys
import argparse
import glob
import BaseHTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
import datetime
import base64
import requests
import psutil

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
            #Load css file
            if self.path.endswith(".css"):
                f = open(self.path[1:])
                self.send_response(200)
                self.send_header('Content-type', 'text/css')
                self.end_headers()
                self.wfile.write(f.read())
                f.close()
                return
            
            #Crash monitor page
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
            
            #get fuzzer info from fuzzer id (hostname:port/10000.info)
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

                        if SHOW_QUEUE:
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
        
SHOW_QUEUE = False

#need parent folder of afl output folder
#-b is option using asan to recheck crash

parser = argparse.ArgumentParser(description='AFL Manager')
parser.add_argument('-i', action="store", dest="input_data", required=True, help='input directory with test cases ')
parser.add_argument('-b', action="store", dest="binary", required=True,help="path to fuzzed_app ")
parser.add_argument('-c', action="store", dest ="asan_binary",required=False,help="path to asan binary (for re-check)")
parser.add_argument('-x', action="store", dest ="dictionary",required=True,help="dictionary file")
parser.add_argument('-a', action="store", dest="authen", required=True,help="authencation with format user:pass")
parser.add_argument("-q","--queue", help="show queue", action="store_true")

args = parser.parse_args()

input_data = args.input_data

cmd = args.binary

if args.asan_binary:
    asan_binary = args.asan_binary
    if not os.path.exists(asan_binary):
        print "[-]Oops, asan binary seem not exits"
        sys.exit()
else:
    print "[-]Fuzzing without verify crash"


if args.dictionary:
    dictionary = args.dictionary
else:
    print "[-]Fuzzing without dictionary"
    dictionary = None

key = base64.b64encode(args.authen)

if args.queue:
        print "[+]Queue data will show up"
        SHOW_QUEUE = True


if not cmd:
    #if we dont have binary, we wont create new alf
    print("[*]No input binary, using afl info at default")
    lafl=[]
    cpu=psutil.cpu_count()
    for i in range(cpu/2):
        afl = Afl(cmd,input_data,"sync/out_"+str(i),dictionary,asan_binary)
        if not afl.update_build_info():
            print "Unable to get instance"
        else:
            afl.update_crash_info()
            lafl.append(afl)

else:
    if not os.path.exists(cmd):
        print("[-]Oops, binary seem not exists (%s)\ncheck pls",cmd)
        sys.exit()
        
    print("Cleaning....")
    os.system("rm -rf sync/*")

    if not os.path.exists('sync'):
        os.mkdir('sync')

    print "[*] Creating fuzzer..."

    lafl=[]
    cpu=psutil.cpu_count()
    for i in range(cpu/2):
        afl = Afl(cmd,input_data,"sync/out_"+str(i),dictionary,asan_binary)
        afl.fuzzer_start()
        time.sleep(1)
        if not afl.update_build_info():
            print "Unable to create instance"
        else:
            afl.update_crash_info()
            lafl.append(afl)

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