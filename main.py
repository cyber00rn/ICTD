import sys
import getopt
from multiprocessing import Process, Queue

from network.network_capture import NetworkCapture
from processor.local_process_unit import LocalProcessUnit
from processor.db_accessor import DataBaseAccessor

dev = 'eth0'

if __name__ == '__main__':

    host = '127.0.0.1'
    port = 54321
    dbname = 'dummy'
    user = 'dummy'
    password = 'dummy'

    opts,args = getopt.getopt(sys.argv[1:], '-h-D:-H:-p:-N:-U:-P:', ['help','network_device=', 'database_host=', 'database_port=', 'database_name=', 'database_user=', 'database_password='])

    for opt_name, opt_value in opts:
        if opt_name in ('-h', '--help'):
            print('use -D(--network_device=) to monitor network device you want, or use default(eth0)')
            print('use -H(--database_host=) to setup database host address')
            print('use -p(--database_port=) to assign database port')
            print('use -N(--database_name=) to setup your database name')
            print('use -U(--database_user=) to setup database user')
            print('use -P(--database_password=) to setup database password')
            print('use -h(--help) to get help message')
            sys.exit()
        if opt_name in ('-D', '--network_device'):
            dev = opt_value
            print('monitor ', dev, ' packet')
        if opt_name in ('-H', '--database_host'):
            host = opt_value
        if opt_name in ('-p', '--database_port'):
            port = opt_value
        if opt_name in ('-N', '--database_name'):
            dbname = opt_value
        if opt_name in ('-U', '--database_user'):
            user = opt_value
        if opt_name in ('-P', '--database_password'):
            password = opt_value

    """Queue size"""
    QUEUE_SIZE = 20000

    testDb = DataBaseAccessor(host, port, user, dbname, password)
    testProcess = LocalProcessUnit(testDb.sql)

    testNetwork = NetworkCapture(testProcess.lpu, dev)

    p = Process(target=testNetwork.capture, args=())
    p2 = Process(target=testProcess.get_packet, args=())
    p3 = Process(target=testDb.exec_sql, args=())
    p.start()
    p2.start()
    p3.start()
    p.join()
    p2.join()
    p3.join()
