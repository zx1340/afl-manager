from utils import *
import ntpath


#Read from afl output folder and gen html 
class Afl():
    def __init__(self,path,cmd = None):
        print "-"*4,path
        self.infname = ''
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
            if 'command_line' in line:
                self.command_line = line.split(':')[1]
        
        parent_cmd  = os.path.split(self.path)[0]
        if not self.cmd:
            self.cmd = os.path.join(parent_cmd, self.command_line.split('--')[1].replace(' ','').replace('@@',''))



    def get_build_info(self):
        self.update_build_info()
        runtime = ms_d(self.last_update - self.start_time)
        last_crash = l_crs(self.last_update - self.last_crash) if self.last_crash  else 'Not yet'
        name = get_fz_name(self.command_line)
        #5 min no update mean stopped 
        status = '[Running]' if (int(time.time()  - self.last_update)) < 300 else '<font color="red">[STOPPED]</font>'
        return ("<tr>" + table_construct(name,\
                                        runtime,\
                                        self.execs_per_sec,\
                                        self.unique_crashes,\
                                        last_crash,\
                                        self.paths_total,\
                                        status)\
                                        + "<td><a href='" + str(self.fuzzer_pid) + ".info'>View</a></td>\
                </tr>")

    def update_crash_info(self):
        #print "INSIDE:", [t[0] for t in self.crash.values()]

        crash_fd_path = self.path + '/crashes'
        if os.path.exists(crash_fd_path):
            all_rb = glob.glob(crash_fd_path + '/*')
            for fname in all_rb:
                # if 'id:000000' in fname:
                #     print "Now fname is id0"
                #     print [t[0] for t in self.crash.values()]
                if fname.endswith('.txt'):
                    pass
                
                elif not len(self.crash) or fname not in [t[0] for t in self.crash.values()]:
                    #print "Scanning",fname
                    command = Command(self.cmd,fname)
                    command.run(timeout = 1)
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
                else:
                    pass

    def get_full_crash_info(self):
        self.update_crash_info()
        
        ret = ''
        for crs in sorted(self.crash, reverse=True):
            #if self.crash[crs][1] != 'Timeout' and self.crash[crs][1] !=  'No crash':
            ret += "<tr>" + table_construct(to_time(crs),\
                                            ntpath.basename(self.crash[crs][0]),\
                                            self.crash[crs][1]) \
                                            + "</tr>"
        return ret

    def get_crash_info(self):
        self.update_crash_info()
        ret = ''
        for crs in sorted(self.crash, reverse=True):
            #print self.crash[crs]
            if self.crash[crs][1] != 'Timeout' and self.crash[crs][1] != 'No crash':
                ret += "<tr>" + table_construct(self.path.split('/')[-1],\
                                                to_time(crs),\
                                                ntpath.basename(self.crash[crs][0]),\
                                                self.crash[crs][1])\
                                                + "</tr>"
        return ret
    
    def get_queue(self):
        ret = ''
        
        #list_of_files = glob.glob(self.path + '/queue/*') # * means all if need specific format then *.csv
        
        #latest_file = max(list_of_files, key=os.path.getctime)
        infname = glob.glob(self.path + '/queue/*id:000000,orig*')[0]
        latest_file = glob.glob((self.path + '/queue/*id:' + '{:06d}'.format(int(self.paths_total) - 1) + '*'))[0]

        print infname,latest_file
        indata = fread(infname)
        data = fread(latest_file)
        

        ret += "<tr><td>"+ infname +"</td><td><pre><code>" + indata + "</code></pre></td>"
        data = fread(latest_file)
        ret += "<tr><td>"+ latest_file +"</td><td><pre><code>" + data + "</code></pre></td>"
        return ret
