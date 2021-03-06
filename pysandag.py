#!/usr/bin/env python

import os, pwd, sys
import ConfigParser
import nids
import getopt
import datetime
import time
import traceback
from pysand import sand

end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

asset_mapdict = {}
topology_mapdict = {}

asset_list = []
fact_list = []

def main(interface,pcapfile,identdir, debug, results, nr, mapfile, outfile):
    global asset_list, fact_list
    if mapfile:
        mapping_config = ConfigParser.ConfigParser()
        mapping_config.read(mapfile)
        if mapping_config.has_section('assets'):
            for mapping in mapping_config.items('assets'):
                asset_mapdict[mapping[1]] = mapping[0]
        if mapping_config.has_section('topologies'):
            for mapping in mapping_config.items('topologies'):
                asset_mapdict[mapping[1]] = mapping[0]
    libsand = sand(newStream,idStream,endStream,identdir,pcapfile,interface,
                   debug_mode=debug, print_results=results, notroot=nr)
    fact_list.sort()
    asset_list.sort()
    if results or outfile:
        network_model = "network model =\n\tassets :\n"
        for asset in asset_list:
            network_model += "\t\t" + asset + ";\n"
        network_model += "\tfacts :\n"
        for fact in fact_list:
            network_model += "\t\t" + fact + ";\n"
        network_model+=".\n"
    if results: print network_model
    if outfile:
        outfile_file = open(outfile, 'w')
        outfile_file.write(network_model)
        outfile_file.close()
    

def get_asset_name(addr):
    if addr in asset_mapdict:
        return asset_mapdict[addr]
    else:
        addr_octets = addr.split('.')
        addr_octets = map(lambda a: a.rjust(3,'0'), addr_octets) # 0-pad IP
        return '_'.join(addr_octets)

def get_topology_name(proto):
    if proto in topology_mapdict:
        return topology_mapdict[proto]
    else:
        return 'connected_network_' + proto.lower()
    # TODO: network vs. adjacent?

def add_to_list(setlist, facts):
    for fact in facts:
        if fact not in setlist:
            setlist.append(fact)

def newStream(tcp_stream):
    global asset_list, fact_list

    add_to_list(asset_list, [get_asset_name(tcp_stream.addr[0][0]),
                   get_asset_name(tcp_stream.addr[1][0])])
    add_to_list(fact_list, ["quality:"+get_asset_name(tcp_stream.addr[0][0])+\
        ",status" + "=up",
        "quality:" + get_asset_name(tcp_stream.addr[1][0]) + \
        ",status" + "=up"])

def idStream(tcp_stream, proto_name):
    global fact_list
    add_to_list(fact_list,["topology:" + get_asset_name(tcp_stream.addr[0][0])\
        + "->" + \
        get_asset_name(tcp_stream.addr[1][0]) + "," + \
        get_topology_name(proto_name)])

def endStream(tcp_stream):
    pass

def usage():
    print 'sudo python pysand.py -s identdir [-m mapfile]\
    {-i interface | -p pcapfile} [-u username] [-o outfile] [-vr]'
    print 'v: verbose'
    print 'r: results'
    print 'u: user to run as'
    print 'm: asset name/IP mapping file'
    print 'o: network model output file'

if __name__ == '__main__':
    interface=None
    pcapfile=None
    identdir=None
    mapfile=None
    outfile=None
    debug=False
    results=False
    user='root'
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hp:i:s:vru:m:o:")
    except getopt.GetoptError, err:
        # print help information and exit:
        print str(err) # will print something like "option -a not recognized"
        usage()
        sys.exit(2)
    for o, a in opts:
        if o == "-p":
            pcapfile=a
        elif o == "-s":
            identdir=a
        elif o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-i"):
            interface=a
        elif o == '-v':
            debug=True
        elif o == '-r':
            results=True
        elif o == '-u':
            user=a
        elif o == '-m':
            mapfile=a
        elif o == '-o':
            outfile=a
        else:
            usage()
            exit()
    if pcapfile==None and interface==None:
        usage()
        exit()
    if pcapfile!=None and interface!=None:
        usage()
        exit()
    if identdir==None:
        usage()
        exit()
    
    main(interface,pcapfile,identdir, debug, results, user, mapfile, outfile)
