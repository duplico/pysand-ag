#!/usr/bin/env python

import os, pwd, sys
import nids
import getopt
import datetime
from ident_gen import *
import time
import traceback

end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

class certainty_node: # One per protocol per stream
    
    """Describes a single cell in the certainty table: matches per stream per signature.
    
    The certainty table consists of a table of certainty nodes, with each certainty
    node representing our level of certainty that a particular stream belongs to
    a particular protocol. It also contains some basic utility for selecting the
    next string to search for from a protocol identifier.
    
    """
    
    def __init__(self, identifier, debug):
        """Construct a new certainty node based on an identifier object.
        
        """
        self.ident=identifier
        self.next={'c': 0, 's': 0}
        self.curs={'c': 0, 's': 0}
        self.certainty=0
        self.debug=debug
    
    def next_search(self,half_stream='c'):
        """Return the next signature to search a half-stream for.
        
        Which half-stream's next signature is determined by the character passed
        to the half_stream parameter, which defaults to client.
        
        :param string half_stream: the half-stream to use: 'c' for client or 's' for server.
        
        :returns tuple: The next signature to search for.
        
        """
        
        assert(half_stream in ('c','s'))
        
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
    
    """Main pysand class for identifying protocols in pcapfiles or from the wire.
    
    The correct way to use this class is by initializing a singleton object,
    passing it functions to be called for callback events. Other processing
    should be done in a separate analysis module. Callbacks are currently
    provided for the detection of a new stream, the identification of a stream,
    and the closure of a stream. Analysis modules should not need to use any
    class except this one.
    
    Pysand will read packets either from the wire (from a specified interface or
    the default interface) or from a specified pcap file; when a new stream is
    detected, the *detect* callback function will be called; when a stream is
    associated with a protocol, the *id* callback function will be called; and
    when a stream is disconnected, the *end* callback function will be called.
    
    Identification can begin immediately or on a delay; debugging information
    can be enabled, in which case it will be sent to StdOut. Optionally,
    results of the detection may be printed to StdOut by pysand.
    
    The new pysand object will use the tcp callbacks specified, identifying
    all of the protocols with identifiers in the identifier directory, and
    read either from the wire (if no pcap file is specified) or from a
    pcap file. If neither a network interface nor a pcap file is specified,
    pysand will attempt to capture from the default network interface.
    
    Due to Python's `Global Interpreter Lock <http://docs.python.org/c-api/init.html#thread-state-and-the-global-interpreter-lock>`_,
    instantiating more than one object of this class at a time will cause
    problems.
    
    Tested in Ubuntu, various versions. Do something like this::
    
    # apt-get install libnet-dev libpcap-dev build-essential python-dev
    # easy_install sphinx
    # wget http://pilcrow.madison.wi.us/pynids/pynids-0.5.tar.gz
    # tar -xzvf pynids-0.5.tar.gz
    # cd pynids-0.5
    
    You need to change the #elif on line ``408`` of libnids-1.19/src/killtcp.c to an
    ``#else``. You may also need to run ``$ export CFLAGS=$CFLAGS -fPIC`` Then::
    
    # python setup.py build
    # python setup.py install
    
    :param function detect_callback_tcp: Callback function for new stream detection
    :param function id_callback_tcp: Callback function for stream identification
    :param function end_callback_tcp: Callback function for stream closing
    :param string identifier_dir: Directory to load identifier files from
    :param string pcap_file: Path to pcap file from which to read traffic
    :param string pcap_interface: Interface from which to sniff packets
    :param string notroot: Non-root user to switch to during execution
    :param boolean debug_mode: Whether to print debugging messages
    :param boolean print_results: Whether to print result information after execution.
    :param boolean go: Whether to run immediately after initialization.
    :param int pcap_timeout: The pcap read timeout, whose support is platform dependent.
    
    """
    
    def __init__(self, detect_callback_tcp, id_callback_tcp, end_callback_tcp,
                 identifier_dir, pcap_file=None, pcap_interface=None,
                 notroot="root", debug_mode=False, print_results=False,
                 go=True, pcap_timeout=1024):
        """Construct a new pysand object.

        :param function detect_callback_tcp: Callback function for new stream detection
        :param function id_callback_tcp: Callback function for stream identification
        :param function end_callback_tcp: Callback function for stream closing
        :param string identifier_dir: Directory to load identifier files from
        :param string pcap_file: Path to pcap file from which to read traffic
        :param string pcap_interface: Interface from which to sniff packets
        :param string notroot: Non-root user to switch to during execution
        :param boolean debug_mode: Whether to print debugging messages
        :param boolean print_results: Whether to print result information after execution.
        :param boolean go: Whether to run immediately after initialization.
        :param int pcap_timeout: The pcap read timeout, whose support is platform dependent.
        
        """
        
        # Instance variables for configuration
        self.debug=debug_mode        
        self.stop_when_possible=False #TODO: make useful or merge w/ go


        # Load all the identifiers from the specified directory.
        if self.debug: print 'Loading identifiers from', identifier_dir
        self.all_idents=self.load_idents(identifier_dir)
        
        # Storage init
        self.next_index=0
        self.stream_table=dict()
        self.index_table=dict()
        
        # Set up libnids
        nids.param("scan_num_hosts", 0)  # Disable portscan detection.
        if pcap_file is not None:
            nids.param("filename", pcap_file)
        if pcap_interface is not None:
            nids.param("device", pcap_interface)
        nids.param("pcap_filter", "tcp") # Only capture TCP traffic for now.
        nids.param("pcap_timeout",pcap_timeout)
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
        # TODO: libraries shouldn't print.
        # TODO (two years later): libraries *seriously* shouldn't print.
        print "pysand pid: [", os.getpid(),']'
    
        start_time = datetime.datetime.now()
        # Loop forever (network device), or until EOF (pcap file)
        # Note that an exception in the callback will break the loop!
        # TODO: currently no way to undo "go".
        if go:
            try:
                if self.debug: print 'going'
                i=1
                while i>0:
                    i=nids.next()
            except nids.error, e:
                print "nids/pcap error:", e
            except KeyboardInterrupt:
                print 'Interrupted by user.'
            except Exception, e:
                print "misc. exception (runtime error in user callback?):"
                traceback.print_exc()
            finally:
                end_time=datetime.datetime.now()
                if self.debug or print_results:
                    for index,strm in self.index_table.iteritems():
                        print "State of stream", strm[2], ",", str(strm[0].addr), ":", strm[0].nids_state,":",strm[3]
                    run_time=str(end_time-start_time)
                    print 'Took',run_time
    
    def step(self, *args):
        if self.debug: print 'Dispatching'
        try:
            nids.dispatch(-1)
        except nids.error, e:
            print "nids/pcap error:", e
        except KeyboardInterrupt:
            print 'Interrupted by user.'
        except Exception, e:
            print "misc. exception (runtime error in user callback?):", e
        if self.debug: print 'Done dispatching.'
    
    def load_idents(self, ident_dir):
        """Load into memory all of the protocol identifiers from ident_dir."""
        identifiers=[]
        for file in os.listdir(ident_dir): # For every file in ident_dir
            new_identifier = load_ident(os.path.join(ident_dir,file))
            if self.debug: print 'Loading identifier: ', load_ident(os.path.join(ident_dir,file))
            if new_identifier is not None:
                identifiers+=[new_identifier]
                if self.debug: print "Added",os.path.join(ident_dir,file)
        return identifiers

    def cease(self):
        # TODO: make this do something
        self.stop_when_possible=True
        exit()

    def handleTcpStream(self, tcp_stream):
        """Callback function called by libnids when it receives a new packet."""
        stream_id=tcp_stream.addr
        

        
        if self.debug: print "Handling a TCP stream.", "Time: ", time, " ",stream_id
        
        if tcp_stream.nids_state == nids.NIDS_JUST_EST: # New connection/stream
            if self.debug: print "New stream.", stream_id
            #self.stream_list = self.stream_list+[tcp_stream]
            tcp_stream.client.collect=1 # Signal to collect this data
            tcp_stream.server.collect=1
            
            # Store our own metadata -- twice.
            new_ct=self.certainty_table(self.all_idents)
            self.index_table[self.next_index]=(tcp_stream,new_ct,stream_id,'unknown') #TODO: These tuples should probably be the same.
            self.stream_table[stream_id]=(self.next_index,new_ct,tcp_stream,'unknown')
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
                    if self.debug: print "Search Term: " + str(search_term)
                    if search_term is not None: # None => no more client sigs to find.
                        found_loc = str(data[half_stream]).find(cert_node.next_search(half_stream)[0]) #, cert_node.curs[half_stream])
                        # TODO: this debug line is very, very, very verbose.
                        if self.debug: print "Searching for",cert_node.next_search(half_stream)[0], "in",half_stream,"in",stream_id
                        if found_loc is not -1:
                            cert_node.certainty+=1
                            if self.debug: print "I found",cert_node.next_search(half_stream)[0],"-- Certainty of ID is ", cert_node.certainty, " / ", cert_node.ident.threshold
                            # TODO: I think I may have been debugging something here -George
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
    print "New stream opened: ", tcp_stream.addr

def idStream(tcp_stream, proto_name):
    pass
    print "Identification made:", tcp_stream.addr, "is", proto_name

def endStream(tcp_stream):
    pass
    print "Stream closed: ", tcp_stream.addr

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
    main(interface,pcapfile,identdir, debug, results, user)
