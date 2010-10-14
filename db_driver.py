import datetime
import MySQLdb
import getopt
import sys
from pysand import sand

dbb = None
# TODO: enable overwriting of these defaults.
database_host = "localhost"
database_user = "raven"
database_passwd = "ravenpass"
database_db = "RAVENDB"

arrived_times = dict()

def main(interface,pcapfile,identdir, debug, results, nr):
    # TODO: init: database_host, database_user, database_passwd, database_db
    # TODO: probably catch some exception on the connection.
    dbb = MySQLdb.connect(host=database_host, user=database_user,
                          passwd=database_passwd, db=database_db)
    try:
        libsand = sand(newStream,idStream,endStream,identdir,pcapfile,interface, debug_mode=debug, print_results=results, notroot=nr)
    finally:
        if dbb is not None:
            dbb.close()
    pass

def newStream(tcp_stream):
    # Save the time that the detected stream was first opened.
    arrived_times[tcp_stream] = datetime.datetime.now()
    print "New stream opened: ", tcp_stream.addr

def idStream(tcp_stream, proto_name):
    # Stream identified, so write it to the database using the timestamp from
    # when the stream was first detected.
    print "Identification made:", tcp_stream.addr, "is", proto_name
    srcIP = tcp_stream[0][0]
    destIP = tcp_stream[1][0]
    time = arrived_times[tcp_stream]
    print "SourceIP: %s, DestIP: %s, Time: %s", (srcIP, destIP, str(time))
    
    c = dbb.cursor()
    sql = "INSERT INTO streams (SrcIP, DestIP, TimeStamp) VALUES (%s, %s, %s)"
    
    try:
        c.execute(sql, (srcIP, destIP, time))
        dbb.commit()
    except MySQLdb.Error, e:
        dbb.rollback()
        print "Error: %d: %s:" % (e.args[0], e.args[1])


def endStream(tcp_stream):
    pass
    #print "Stream closed: ", tcp_stream.addr

def usage():
    print 'sudo python db_driver.py -s identdir {-i interface | -p pcapfile} [-u username] [-vr]'
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
