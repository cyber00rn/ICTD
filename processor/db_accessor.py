import psycopg2
from psycopg2.extras import execute_batch
from multiprocessing import Queue
import time

from utils.print_log import Printer
import logging

class DataBaseAccessor():
    QUEUE_SIZE = 20000
    alive = True
    status = False

    def convertTuple(self, tup):
        str =  ', '.join(tup)
        return str

    def __init__(self, host: str, port: int, user: str, dbname: str, password:str, queue_size=QUEUE_SIZE):
        self.assigned_queue_size = queue_size
        self.sql = Queue(self.assigned_queue_size)
        self.conn_string = "host={0} port={1} user={2} dbname={3} password={4}".format(host, port, user, dbname, password)
        self.db_exec_count = 0
        self.total_db_exec_count = 0
        self.printer = Printer()
        try:
            self.conn = psycopg2.connect(self.conn_string)
            self.cursor = self.conn.cursor()
            self.status = True
        except Exception as e:
            self.printer.error("Occur error " + str(e))

    def exec_sql(self):
        while self.alive:
            if self.status == True:
                self.printer.debug("qsize: " + str(self.sql.qsize()) + ", db_exec_count: " + str(self.db_exec_count))
                sql = self.sql.get()
                cmd = sql.get('sql')
                val = sql.get('sql_val')
                try:
                    query = self.cursor.mogrify(sql, val)
                    self.cursor.execute(query)
                    self.conn.commit()
                    self.db_exec_count += 1
                except Exception as e:
                    self.printer.error("Occur error " + str(e))
                    self.reset_conn()
                if self.db_exec_count > 100000:
                    self.reset_conn()

    def exit(self):
        self.alive = False
        self.cursor.close()
        self.conn.close()

    def reset_conn(self):
        self.status = False
        self.total_db_exec_count += self.db_exec_count
        self.printer.debug('reset db connection, db_exec_count: ' + str(self.db_exec_count) + ', total: ' + str(self.total_db_exec_count))
        self.cursor.close()
        self.conn.close()
        time.sleep(1)
        try:
            self.conn = psycopg2.connect(self.conn_string)
            self.cursor = self.conn.cursor()
            self.status = True
            self.db_exec_count = 0
        except Exception as e:
            self.printer.error("Occur error " + str(e))
            f = open("/tmp/db_failed", "w")
            f.close()
            self.exit()
