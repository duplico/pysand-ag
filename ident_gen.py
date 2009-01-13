#!/usr/bin/env python

import os, ConfigParser
from pysand import *

class gen_ident:
    def __init__(self, proto_name, client_signature_list, server_signature_list, threshold):
        self.proto_name=proto_name
        #client_signature_list
        self.s_sigs=server_signature_list
        self.c_sigs=client_signature_list
        self.threshold=threshold
        
    def __str__(self):
        return "GEN_IDENT:"+str(self.proto_name)+str(self.s_sigs)+str(self.c_sigs)+str(self.threshold)

def load_ident(filename):
    config = ConfigParser.ConfigParser()
    config.read([filename])
    all_sections=config.sections()
    num_client=0
    num_server=0
    server_working=True
    client_working=True
    for i in range(len(all_sections)):
        if client_working and "client"+str(i) in all_sections:
            #print i,"c"
            pass
        elif client_working:
            num_client=i
            #print num_client,"clients"
            client_working=False
        if server_working and "server"+str(i) in all_sections:
            #print i,"s"
            pass
        elif server_working:
            num_server=i
            #print num_server,"servers"
            server_working=False
    for section in all_sections:
        if section is not 'identifier' and section.startswith('server') and section.startswith('client'):
            print "Invalid section in identifier", filename
            return None
    if len(all_sections) != num_client+num_server+1:
        print "Wrong number of sections --", len(all_sections), "-- in identifier", filename
        print "Expected sections: ", str(num_client+num_server+1)
        return None
    
    # Get client signatures
    client_list=[]
    for i in range(num_client):
        client_list+=[(config.get('client'+str(i),'start').strip('"').decode('string_escape'),config.get('client'+str(i),'sig').strip('"'),config.get('client'+str(i),'finish').strip('"').decode('string_escape'))]
    
    # Get server signatures
    server_list=[]
    for i in range(num_server):
        server_list+=[(config.get('server'+str(i),'start').strip('"').decode('string_escape'),config.get('server'+str(i),'sig').strip('"'),config.get('server'+str(i),'finish').strip('"').decode('string_escape'))]
    
    # Generate the new identifier and return it    
    return gen_ident(config.get('identifier','protocol').strip('"'),client_list,server_list,config.getint('identifier','threshold'))