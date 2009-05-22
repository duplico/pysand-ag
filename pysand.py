#!/usr/bin/env python

import os, pwd, sys
import nids
import getopt
import datetime
from ident_gen import *

end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

#DEBUG=False

class certainty_node: # One per protocol per stream
    """A certainty node describes a single node in the certainty table;
    there should exist a single certainty node per protocol per stream.
    It handles tracking our certainty about its identification."""
    def __init__(self, identifier, debug):
        """Construct a new certainty node based on an identifier object."""
        self.ident=identifier
        self.next={'c': 0, 's': 0}
        self.curs={'c': 0, 's': 0}
        self.certainty=0
        self.debug=debug
    
    def next_search(self,half_stream='c'):
        """Returns the next string to search the half-stream for, depending
        upon the character that is passed as the half_stream parameter.
        Returns None if there are no more signatures to find in the half-stream.
        c->client half-stream (default)
        s->server half-stream"""
        
        # Enforce default behavior. I hope this never happens.
        if half_stream not in ('c','s'):
            half_stream='c'
            if self.debug: print "Forcing client search. Fix your coding, stupid."
        
        # Select the proper set of signatures
        if half_stream=='c':
            sigs=self.ident.c_sigs
        else:
            sigs=self.ident.s_sigs
        
        # Return the proper signature, if it exists. Otherwise None.
        if len(sigs) <= self.next[half_stream]:
            return None
        else:
            return sigs[self.next[half_stream]]


class sand:
    """The main pysand class. Instanciating more than one at a time
    is not recommended (read: will break stuff)."""
    def __init__(self, detect_callback_tcp, id_callback_tcp, end_callback_tcp, identifier_dir, pcap_file=None, pcap_interface=None, notroot="root", debug_mode=False, print_results=False):
        """Construct a new pysand object.
        Parameters:
        detect_callback_tcp: Callback function to be called when a new stream is detected.
        id_callback_tcp: Callback function to be called when a stream is identified.
        end_callback_tcp: Callback function to be called when a stream is closed.
        identifier_dir: The directory containing our identifier specifications.
        pcap_file: Optional. The pcap file to use. If omitted, captures from the wire."""
        
        self.debug=debug_mode
        
        self.stop_when_possible=False
        
        if pcap_file == 'None':
            pcap_file=None
        
        # Load all the identifiers from the specified directory.
        if self.debug: print 'Loading identifiers from', identifier_dir
        self.all_idents=self.load_idents(identifier_dir)
        
        # Storage init
        self.next_index=0
        self.stream_table=dict()
        self.index_table=dict()
        
        ###
        #pcap_file=None
        #pcap_interface='eth0'
        ###
        
        # Set up libnids
        nids.param("scan_num_hosts", 0)  # Disable portscan detection.
        if pcap_file is not None:
            nids.param("filename", pcap_file)
        if pcap_interface is not None:
            nids.param("device", pcap_interface)
        nids.param("pcap_filter", "tcp") # Only capture TCP traffic for now.
        #nids.param("tcp_workarounds",1) I don't think this line was even supported by the Python wrapper anyway.
        nids.init()
        nids.register_tcp(self.handleTcpStream)
        
        
        # SAND Callback functions init
        # Read these instance variables like a sort of mixed Hungarian notation:
        # function_callback_new, identify, end_for tcp protocol
        self.f_cb_new_tcp = detect_callback_tcp
        self.f_cb_id_tcp = id_callback_tcp
        self.f_cb_end_tcp = end_callback_tcp
        if self.debug: print "Callbacks registered"

        # Drop to run as a user
        if notroot is not "root":
            (uid, gid) = pwd.getpwnam(notroot)[2:4]
            os.setgroups([gid,])
            os.setgid(gid) #
            os.setuid(uid)
            if 0 in [os.getuid(), os.getgid()] + list(os.getgroups()):
                print "Supply better username, please!"
                sys.exit(1)
        else:
            print 'Pysand is running as root. This may not be advised.'
        
        # Output our PID. Just in case we have to kill us.
        print "pid: [", os.getpid(),']'
    
        start_time = datetime.datetime.now()
        # Loop forever (network device), or until EOF (pcap file)
        # Note that an exception in the callback will break the loop!
        try:
            i=1
            while i>0:
                i=nids.next()
        except nids.error, e:
            print "nids/pcap error:", e
        except KeyboardInterrupt:
            print 'Interrupted by user.'
        except Exception, e:
            print "misc. exception (runtime error in user callback?):", e
        finally:
            end_time=datetime.datetime.now()
            if self.debug or print_results:
                for index,strm in self.index_table.iteritems():
                    print "State of stream", strm[2], ",", str(strm[0].addr), ":", strm[0].nids_state,":",strm[3]
                    run_time=str(end_time-start_time)
                    print 'Took',run_time

    def load_idents(self, ident_dir):
        """Load into memory all of the protocol identifiers from ident_dir."""
        identifiers=[]
        for file in os.listdir(ident_dir): # For every file in ident_dir
            new_identifier = load_ident(os.path.join(ident_dir,file))
            if self.debug: print 'Loading identifier: ', load_ident(os.path.join(ident_dir,file))
            if new_identifier is not None:
                identifiers+=[new_identifier]
                #print "Added",os.path.join(ident_dir,file)
        return identifiers

    def cease(self):
        self.stop_when_possible=True
        exit()

    def handleTcpStream(self, tcp_stream):
        """Callback function called by libnids when it receives a new packet."""
        stream_id=tcp_stream.addr
        if self.debug: print "Handling a TCP stream.",stream_id
        if tcp_stream.nids_state == nids.NIDS_JUST_EST: # New connection/stream
            if self.debug: print "New stream.", stream_id
            #self.stream_list = self.stream_list+[tcp_stream]
            tcp_stream.client.collect=1 # Signal to collect this data
            tcp_stream.server.collect=1
            
            # Store our own metadata -- twice.
            new_ct=self.certainty_table(self.all_idents)
            self.index_table[self.next_index]=(tcp_stream,new_ct,stream_id,'unknown') #TODO: These tuples should probably be the same.
            self.stream_table[stream_id]=(self.next_index,new_ct,tcp_stream,'unknown')
            #print "*******", tcp_stream.addr,"***",stream_id
            self.next_index+=1
            
            
            self.identifyStream(stream_id)
            self.f_cb_new_tcp(tcp_stream) #Call back.
        elif tcp_stream.nids_state == nids.NIDS_DATA: # Established connection receiving new data
            index=self.stream_table[stream_id][0]
            ct = self.index_table[index][1]
            proto=self.index_table[index][3]
            if proto is 'unknown':
                self.identifyStream(stream_id)
        elif tcp_stream.nids_state in end_states: #TODO: This doesn't seem to work. Except sometimes.
            self.f_cb_end_tcp(tcp_stream)

    def identifyStream(self, stream_id):
        id_ret=self.searchStream(stream_id)
        if id_ret:
            index=self.stream_table[stream_id][0]
            tcp_stream=self.stream_table[stream_id][2]
            ct=self.stream_table[stream_id][1]
            self.stream_table[stream_id]=(index,ct,tcp_stream,id_ret)
            self.index_table[index]=(tcp_stream,ct,stream_id,id_ret)
            self.f_cb_id_tcp(self.stream_table[stream_id][2], id_ret)
        pass
        
    def searchStream(self,stream_id):
        tcp_stream=self.stream_table[stream_id][2]
        data = dict()
        # There's a lot going on in the following lines that is, at first, unintuitive.
        # First of all, due to weirdness somewhere in libnids (I'm quite sure it's not
        # in the pysand code), their representation of the client does not jibe with
        # our representation of a client. Somewhere in the pysand code, therefore,
        # they need to be swapped. This is where that happens, and only here (I hope).
        # Secondly, the data that libnids stores is held in a (by default) 4096-byte buffer;
        # the pynids wrapper gives me direct access to this, so if I ask Python for
        # the length of the data that I've gotten so far, it will always tell me
        # 4096. The problem is that if I have less than 4096 bytes of data from a single
        # half-stream, unpredictable behavior results. So let's make sure we're only
        # going to search the correct substring.
        # Whew! --George
        data['c'] = tcp_stream.server.data[:tcp_stream.server.count]
        data['s'] = tcp_stream.client.data[:tcp_stream.client.count]
        if self.debug: print "Length of ", stream_id, len(str(data['c'])), len(str(data['s']))
        for cert_index in self.stream_table[stream_id][1]: # For each protocol node in a certainty table
            cert_node=self.stream_table[stream_id][1][cert_index]
            for half_stream in ('s','c'):   # For each TCP half-stream
                search_term=None
                while search_term is not cert_node.next_search(half_stream):
                    search_term=cert_node.next_search(half_stream)
                    if search_term is not None: # None => no more client sigs to find.
                        found_loc = str(data[half_stream]).find(cert_node.next_search(half_stream)[0]) #, cert_node.curs[half_stream])
                        if self.debug: print "Searching for",cert_node.next_search(half_stream)[0], "in",half_stream,"in",stream_id
                        if found_loc is not -1:
                            cert_node.certainty+=1
                            if self.debug: print "I found",cert_node.next_search(half_stream)[0],"-- Certainty of ID is ", cert_node.certainty, " / ", cert_node.ident.threshold
                            #print cert_node.next_search(half_stream)[0], "in\n",str(data[half_stream])
                            cert_node.next[half_stream]+=1
                            if cert_node.certainty == cert_node.ident.threshold:
                                tcp_stream.client.collect = 0
                                tcp_stream.server.collect = 0
                                return cert_node.ident.proto_name
                        else:
                            pass
                    else:
                        if self.debug: print "No more sigs to find."
        return False
                    
    
    def certainty_table(self,identifiers):
        ct=dict()
        for i in identifiers:
            ct[i.proto_name]=certainty_node(i, self.debug)
        return ct

def main(interface,pcapfile,identdir, debug, results, nr):
    libsand = sand(newStream,idStream,endStream,identdir,pcapfile,interface, debug_mode=debug, print_results=results, notroot=nr)
    pass

def newStream(tcp_stream):
    pass
    #print "New stream opened: ", tcp_stream.addr

def idStream(tcp_stream, proto_name):
    pass
    #print "Identification made:", tcp_stream.addr, "is", proto_name
    tcp_stream=None

def endStream(tcp_stream):
    pass
    #print "Stream closed: ", tcp_stream.addr

def usage():
    print 'sudo python pysand.py -s identdir {-i interface | -p pcapfile} [-u username] [-vr]'
    print 'v: verbose'
    print 'r: results'
    print 'u: user to run as'

if __name__ == '__main__':
    interface=None
    pcapfile=None
    identdir=None
    debug=False
    results=False
    user='root'
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hp:i:s:vru:")
    except getopt.GetoptError, err:
        # print help information and exit:
        print str(err) # will print something like "option -a not recognized"
        usage()
        sys.exit(2)
    for o, a in opts:
        if o == "-p":
            pcapfile=a
        if o == "-s":
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
        else:
            usage()
    if pcapfile==None and interface==None:
        usage()
        exit()
    if pcapfile!=None and interface!=None:
        usage()
        exit()
    if identdir==None:
        usage()
        exit()        
    main(interface,pcapfile,identdir, debug, results, user)
