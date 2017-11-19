
import os
import sys
import time
import threading
import thread
import subprocess
import argparse
import glob
import BaseHTTPServer
import ntpath
import datetime

HOST_NAME = '0.0.0.0'
PORT_NUMBER = 1340


web_start ="""
<head>
  <title>AFL manager</title>
  <link rel="stylesheet" type="text/css" href="source.css">

</head>
<body>
<h1><span class="blue">&lt;</span>AFL<span class="blue">&gt;</span> <span class="yellow">MANAGER</pan></h1>
<h2></h2>

<table class="container">
  <thead>
    <tr>
      <th><h1>Name</h1></th>
      <th><h1>Run time</h1></th>
      <th><h1>Speed</h1></th>
      <th><h1>Crash</h1></th>
      <th><h1>Last crash</h1></th>
      <th><h1>Cov</h1></th>
      <th><h1>Status</h1></th>
      <th><h1>View</h1></th>
    </tr>
  </thead>
  <tbody>
"""

web_end = """</tbody>
</table>
</span>
</h1>
</body>
"""

crash_start = """
<head>
  <title>AFL manager</title>
  <link rel="stylesheet" type="text/css" href="source.css">

</head>
<body>
<h1><span class="blue">&lt;</span>AFL<span class="blue">&gt;</span> <span class="yellow">MANAGER</pan></h1>
<h2></h2>

<table class="container">
  <thead>
    <tr>
      <th><h1>Created Time</h1></th>
      <th><h1>Name</h1></th>
      <th><h1>Info</h1></th>
    </tr>
  </thead>
  <tbody>
"""

def to_time(t):
    return datetime.datetime.fromtimestamp(int(t)).strftime('%Y-%m-%d %H:%M:%S')

def current_time():
    return str(repr(time.time()))


#$python asd.py -> kill process contain asd.py
def kill_process(fname):
    prcid = []
    process = subprocess.Popen(['ps','aux'], stdout=subprocess.PIPE, stderr= subprocess.PIPE)
    result,error = process.communicate()
    result_line = result.split('\n')
    for i in result_line:
        if fname in i:
            p_spl = i.split(' ')
            for x in range(2,len(p_spl)):
                if p_spl[x] != '':
                    prcid.append(p_spl[x])
                    break

    for prc_id in prcid:
        os.system('kill -9 ' + prc_id)

#Simply convert out put error to write_able filename
def get_error_name(error):
    errors = error.split('\n')
    for e in errors:
        if "SUMMARY" in e:
            return e.replace(" ",'_').replace('/','_').replace('\\','_').replace('(','_').replace(')','_')

    return current_time()



#Execute command get output and error, using for detect segementation fault
class Command(object):
    def __init__(self, cmd, fname):
        self.cmd = cmd
        self.process = None
        self.fname = fname 				#fuzzing file name
        self.crashed = False
        self.crash_fname = None     	#crash file name
        self.error = False
        self.timeout = False
        self.result = False

    def run(self, timeout):
        def target():

            self.process = subprocess.Popen([self.cmd,self.fname], stdout=subprocess.PIPE, stderr= subprocess.PIPE)
            result,error = self.process.communicate()
            self.result = result
            self.error = error
            if self.error:
                self.crashed = True
                if "AddressSanitizer" in error:
                    self.crash_fname = current_time() +  get_error_name(error) + '.txt'
                else:# 'Assertion failed' in error:
                    self.crash_fname = '_'.join(self.error.split())


        thread = threading.Thread(target=target)
        thread.start()
        thread.join(timeout)
        if thread.is_alive():
            kill_process(self.fname)
            self.timeout = True
            thread.join()


#This function get all file name from directory and sub_directory
def get_all_input(directory):
    file_paths = []  # List which will store all of the full filepaths.
    # Walk the tree.
    for root, directories, files in os.walk(directory):
        for filename in files:
            # Join the two strings in order to form the full filepath.
            if "README" not in filename:
                filepath = os.path.join(root, filename)
                file_paths.append(filepath)  # Add it to the list.

    return file_paths  # Self-explanatory.


#second to day/hrs/min/sec
def ms_d(t):
    m, s = divmod(t, 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    return "%d days, %d hrs, %02d min, %02d sec"% (d, h, m, s)

#second to hrs/min/sec
def ms_h(t):
    m, s = divmod(t, 60)
    h, m = divmod(m, 60)
    return "%d hrs, %02d min, %02d sec ago"% (h, m, s)


def l_crs(t):
    if t > 24*60*60:
        return "%d days ago" % (t/(24*60*60)) 
    return ms_h(t)



#return list of folder contain afl output directory
def get_afl_instance(root):
    root_fd = glob.glob(root + '/*')
    afl_instance = []
    for fd in root_fd:
        fd_out = glob.glob(fd + '/*')
        for fdname in fd_out:
            if os.path.exists(fdname +'/crashes'):
                afl_instance.append(fdname)
    return afl_instance


#Read from afl output folder and gen html 
class Afl():
    def __init__(self,path,cmd = None):
        self.path = path
        self.crash = {}
        self.start_time = None
        self.last_update = None
        self.execs_per_sec = None
        self.paths_total = None
        self.unique_crashes = None
        self.last_crash = None
        self.fuzzer_pid = None
        self.cmd = cmd 
        self.update_build_info()
        self.update_crash_info()

    def update_build_info(self):
        fuzzer_stat_path = self.path + '/fuzzer_stats'

        with open(fuzzer_stat_path,'r') as f:
            data = f.read().split('\n')

        for line in data:
            if 'start_time' in line:
                self.start_time = int(line.split(':')[1])
            if 'last_update' in line:
                self.last_update = int(line.split(':')[1])
            if 'execs_per_sec' in line:
                self.execs_per_sec = line.split(':')[1]
            if 'paths_total' in line:
                self.paths_total = (line.split(':')[1])
            if 'unique_crashes' in line:
                self.unique_crashes = (line.split(':')[1])
            if 'last_crash' in line:
                self.last_crash = int(line.split(':')[1])
            if 'fuzzer_pid' in line:
                self.fuzzer_pid = int(line.split(':')[1])
            if not self.cmd:
                if 'command_line' in line:
                    parent_cmd  = os.path.split(self.path)[0]
                    self.cmd = os.path.join(parent_cmd, line.split(':')[1].split('--')[1].replace(' ','').replace('@@',''))

    def get_build_info(self):
        self.update_build_info()
        runtime = ms_d(self.last_update - self.start_time)
        last_crash = l_crs(self.last_update - self.last_crash) if self.last_crash  else 'Not yet'
        name = self.path.split('/')[-2]
        #5 min no update mean stopped 
        status = '[Running]' if (int(time.time()  - self.last_update)) < 300 else '[Stopped]'
        return ("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><a href='%s.info'>View</a></td></tr>"\
                    %(name,runtime,self.execs_per_sec,self.unique_crashes,last_crash, self.paths_total, status,self.fuzzer_pid) )

    def update_crash_info(self):
        crash_fd_path = self.path + '/crashes'
        if os.path.exists(crash_fd_path):
            all_rb = get_all_input(crash_fd_path)
            for fname in all_rb:
                if not self.crash or fname not in [t[0] for t in self.crash.values()]:
                    print ">",fname
                    command = Command(self.cmd,fname)
                    command.run(timeout = 0.3)
                    if not command.timeout:
                        if not command.error and not command.result:
                            self.crash[os.path.getmtime(fname)] = (fname,"Unknow segmentation fault")
                        else:
                            if command.error:
                                self.crash[os.path.getmtime(fname)] = (fname,command.crash_fname)
                            else:
                                self.crash[os.path.getmtime(fname)] = (fname,"No crash")

                    else:
                        self.crash[os.path.getmtime(fname)] = (fname,"Timeout")

    def get_crash_info(self):
        self.update_crash_info()
        ret = ''
        for crs in sorted(self.crash, reverse=True):
            if self.crash[crs][1] != 'Timeout' and self.crash[crs][1] !=  'No crash':
                ret += "<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (to_time(crs),ntpath.basename(self.crash[crs][0]),self.crash[crs][1])
        return ret

#Simple Http server reponse get
class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_HEAD(s):
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()
    def do_GET(s):
        """Respond to a GET request."""
        if s.path == "/source.css":
            f = open('./' + s.path)
            s.send_response(200)
            s.send_header('Content-type', 'text/css')
            s.end_headers()
            s.wfile.write(f.read())
            f.close()
            return

        if s.path.endswith('.info'):
            s.send_response(200)
            s.send_header("Content-type", "text/html")
            s.end_headers()
            fz_dir = int(s.path[1:-5])
            s.wfile.write(crash_start)
            for afl in lafl:
                if fz_dir == afl.fuzzer_pid:
                    s.wfile.write('<h1 onclick="window.history.go(-1); return false;">' + afl.path.split('/')[-2] + '</h1>')
                    s.wfile.write(afl.get_crash_info())
                    s.wfile.write(web_end)
                    return
            s.wfile.write("There is nothing here")
            return

        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()
        s.wfile.write(web_start)
        
        for afl in lafl:
            s.wfile.write(afl.get_build_info())
        s.wfile.write(web_end)


#need parent folder of afl output folder
#-b is option using asan to recheck crash
parser = argparse.ArgumentParser(description='AFL Manager')
parser.add_argument('-i', action="store", dest="source", required=True, help='Parent directory of AFL')
parser.add_argument('-b', action="store", dest="binary", required=False,help="binary ")
args = parser.parse_args()

source = args.source
cmd = args.binary if args.binary else None


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


