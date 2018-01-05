import datetime
import time
import subprocess
import os
import glob
import threading
import requests
import random


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

def send_notify(info):
  #Send notify to slack
  return 
  headers = {
      'Content-type': 'application/json',
  }
  data = '{"text":"'+ info + '"}'
  if "stack-overflow" not in info:
    requests.post('', headers=headers, data=data)



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
            print self.fname
            self.process = subprocess.Popen([self.cmd,self.fname], stdout=subprocess.PIPE, stderr= subprocess.PIPE)
            result,error = self.process.communicate()
            self.result = result
            self.error = error
            if self.error and "stack-overflow" not in error:
                self.crashed = True
                if "AddressSanitizer" in error:
                    self.crash_fname = current_time() +  get_error_name(error) + '.txt'
                else:# 'Assertion failed' in error:
                    self.crash_fname = '_'.join(self.error.split())
                #send_notify(self.crash_fname)

        thread = threading.Thread(target=target)
        thread.start()
        thread.join(timeout)
        if thread.is_alive() and self.crashed == False:
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

def table_construct(*arg):
    ret = ''
    for i in range(len(arg)):
        ret += "<td>%s</td>" % arg[i]
    return ret

def get_out_fd(cmd):
    dataspl = cmd.split()
    for i in range(len(dataspl)):
        if dataspl[i] == '-o':
            return dataspl[i + 1]

def fread(fname):
    with open(fname,'r') as f:
        data = f.read()
    f.close()
    return data

def get_fz_name(cmd):
    dataspl = cmd.split()
    for i in range(len(dataspl)):
        if dataspl[i] == '-T':
            return dataspl[i + 1]
    return cmd.split()[-2]