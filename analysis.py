import os,glob
import difflib
import argparse
import sys

import logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


#Save info about queue data name and source name

class Queue():
    def __init__(self,queue_name,src_name):
        #logger.warning("[%s] [%s]" %(queue_name,src_name))
        self.queue_name = queue_name
        self.name = get_fname(queue_name) #use for show on page
        self.data = self.get_data(queue_name,src_name)
        self.child = []

    def get_data(self,src_name,queue_name):
        logger.info("[%s] [%s]" %(src_name,queue_name))
        ret = ''

        #src = src_name.split('src:')[1][:6]
        
        src_data = fread(src_name)
                
        queue_data = fread(queue_name)

        d = difflib.Differ()
        
        l = list(d.compare(src_data, queue_data))
        
        for i in l:
            if i.startswith('  '):
                ret += i[2:]
            if i.startswith('- '):
                ret += mark_red(i[2:])
        return ret


class Analysis():

    def __init__(self,all_file,queue_name):
        self.all_file = all_file
        self.queue_name = queue_name
        self.src_list = []

    def get_source_name(self,queue_id):
        logger.info("get parent of %s ", queue_id)
        if len(queue_id) == 6:
            queue_name = get_name_from_id(self.all_file,queue_id)
        else:
            queue_name = queue_id

        return get_name_from_id(self.all_file,queue_name.split('src:')[1][:6])


    def get_queue_tree(self):
        #incase source name is id
        if len(self.queue_name) == 6: 
            self.queue_name = get_name_from_id(self.all_file,self.queue_name)

        logger.info('Got source file %s ' % self.queue_name)

        ret = [ Queue(self.queue_name,self.get_source_name(self.queue_name))]
        ret = []
        queue_name = self.queue_name

        while True:
            if get_id_from_name(queue_name) == '000000':
                #logger.info("Add last")
                ret.append(Queue(get_name_from_id(self.all_file,'000000'),queue_name))
                break


            parent_id = queue_name.split('src:')[1][:6]
            logger.info("PR id %s",parent_id)
            parent_name = get_name_from_id(self.all_file,parent_id)

            logger.info("Add %s",parent_name)
            
            ret.append(Queue(queue_name,self.get_source_name(queue_name)))
            queue_name = parent_name
                
        return ret

def fread(fname):
    with open(fname,'r') as f:
        data = f.read()
    return data

def get_fname(flink):
    return flink.split('/')[-1] if flink else None


def mark_red(data):
    return '<font color="red">' + data + '</font>'

def get_name_from_id(all_file,name):

    for fname in all_file:
        if 'id:' + name in fname:
            return fname

def get_id_from_name(fname):
    return fname.split('id:')[1][:6]



