import dpkt
from multiprocessing import Queue
import socket
from dpkt.compat import compat_ord

from utils.print_log import Printer
import logging

import hashlib

class LocalProcessUnit():
    """Queue size"""
    QUEUE_SIZE = 20000
    alive = True

    def __init__(self, db_queue: Queue, queue_size=QUEUE_SIZE):
        self.dbq = db_queue
        self.lpu = Queue(queue_size)
        self.printer = Printer()

    def mac_addr(self, address):
        """Convert a MAC address to a readable/printable string

        Args:
            address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
        Returns:
            str: Printable/readable MAC address
        """
        return ':'.join('%02x' % compat_ord(b) for b in address)

    def parse_packet(self, timestamp, pkt):
        eth=dpkt.ethernet.Ethernet(pkt)
        res = {}
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            res = self.parse_ipv4(eth.data)
            res['packet_type'] = 'ipv4'
            res['eth_data_len'] = eth.data.len
        elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            res = self.parse_ipv6(eth.data)
            res['packet_type'] = 'ipv6'
        elif eth.type == dpkt.ethernet.ETH_TYPE_ARP:
            # address resolution protocol
            res = self.parse_arp(eth.data)
            res['packet_type'] = 'arp'
        elif eth.type == dpkt.ethernet.ETH_TYPE_REVARP:
            # reverse addr resolution protocol
            res['packet_type'] = 'revarp'
        elif eth.type == dpkt.ethernet.ETH_TYPE_PPPoE:
            res['packet_type'] = 'PPPoE'
        elif eth.type == dpkt.ethernet.ETH_TYPE_EDP:
            # Extreme Networks Discovery Protocol
            res['packet_type'] = 'EDP'
        elif eth.type == dpkt.ethernet.ETH_TYPE_PUP:
            # PUP protocol
            res['packet_type'] = 'PUP'
        elif eth.type == dpkt.ethernet.ETH_TYPE_AOE:
            # AoE protocol
            res['packet_type'] = 'AoE'
        elif eth.type == dpkt.ethernet.ETH_TYPE_CDP:
            # Cisco Discovery Protocol
            res['packet_type'] = 'CDP'
        elif eth.type == dpkt.ethernet.ETH_TYPE_DTP:
            # Cisco Dynamic Trunking Protocol
            res['packet_type'] = 'DTP'
        elif eth.type == dpkt.ethernet.ETH_TYPE_8021Q:
            # IEEE 802.1Q VLAN tagging
            res['packet_type'] = '802.1Q'
        elif eth.type == dpkt.ethernet.ETH_TYPE_8021AD:
            # IEEE 802.1ad
            res['packet_type'] = '802.1ad'
        elif eth.type == dpkt.ethernet.ETH_TYPE_QINQ1:
            # Legacy QinQ
            res['packet_type'] = 'QinQ1'
        elif eth.type == dpkt.ethernet.ETH_TYPE_QINQ2:
            # Legacy QinQ
            res['packet_type'] = 'QinQ2'
        elif eth.type == dpkt.ethernet.ETH_TYPE_IPX:
            res['packet_type'] = 'IPX'
        elif eth.type == dpkt.ethernet.ETH_TYPE_PPP:
            res['packet_type'] = 'PPP'
        elif eth.type == dpkt.ethernet.ETH_TYPE_MPLS:
            res['packet_type'] = 'MPLS'
        elif eth.type == dpkt.ethernet.ETH_TYPE_MPLS_MCAST:
            res['packet_type'] = 'MPLS_MCAST'
        elif eth.type == dpkt.ethernet.ETH_TYPE_PPPoE_DISC:
            res['packet_type'] = 'PPPoE_DISC'
        elif eth.type == dpkt.ethernet.ETH_TYPE_LLDP:
            # Link Layer Discovery Protocol
            res['packet_type'] = 'LLDP'
        elif eth.type == dpkt.ethernet.ETH_TYPE_TEB:
            res['packet_type'] = 'TEB'
        else:
            res['packet_type'] = 'Unkown'

        if res.get('src_mac') == None:
            res['src_mac'] = self.mac_addr(eth.src)
        if res.get('dst_mac') == None:
            res['dst_mac'] = self.mac_addr(eth.dst)

        sql = "INSERT INTO aidata2 (time, packet_type, protocol, src_mac, src_ip, src_port, dst_mac, dst_ip, dest_port, tcp_flags, size, \"offset\", ttl) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);"

        sql_val = (timestamp, res.get('packet_type'), res.get('protocol'), res.get('src_mac'), res.get('src_ip'), res.get('src_port'), res.get('dst_mac'), res.get('dst_ip'), res.get('dest_port'), res.get('tcp_flags'), res.get('len'), res.get('offset'), res.get('ttl'))

        debug_val = (str(timestamp), res.get('packet_type', ""), res.get('protocol', ""), res.get('src_mac', ""), res.get('src_ip', ""), str(res.get('src_port', "")), res.get('dst_mac', ""), res.get('dst_ip', ""), str(res.get('dest_port', "")), res.get('tcp_flags', ""), str(res.get('len', "")), str(res.get('offset', "")), str(res.get('ttl', "")))
        self.dbq.put({'sql': sql, 'sql_val': sql_val, 'debug_val': debug_val})

        m = hashlib.sha256()
        data = res.get('src_mac', "") + '+' + str(timestamp)
        m.update(data.encode("utf-8"))
        hashed = m.hexdigest()

        sql = "INSERT INTO event (flow_id, src_ip, dest_ip, timestamp, protocol) VALUES (%s, %s, %s, %s, %s);"

        sql_val = (hashed, res.get('src_ip'), res.get('dst_ip'), timestamp, res.get('protocol'))

        debug_val = (hashed, res.get('src_ip', ""), res.get('dst_ip', ""), str(timestamp), res.get('protocol', ""))
        self.dbq.put({'sql': sql, 'sql_val': sql_val, 'debug_val': debug_val})

        sql = "INSERT INTO event_detail (flow_id, packet_type, src_mac, src_port, dest_mac, dest_port, tcp_flag, size, \"offset\", ttl) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);"

        sql_val = (hashed, res.get('packet_type'), res.get('src_mac'), res.get('src_port'), res.get('dst_mac'), res.get('dest_port'), res.get('tcp_flags'), res.get('len'), res.get('offset'), res.get('ttl'))

        debug_val = (hashed, res.get('packet_type', ""), res.get('src_mac', ""), str(res.get('src_port', "")), res.get('dst_mac', ""), str(res.get('dest_port', "")), res.get('tcp_flags', ""), str(res.get('len', "")), str(res.get('offset', "")), str(res.get('ttl', "")))
        self.dbq.put({'sql': sql, 'sql_val': sql_val, 'debug_val': debug_val})
        if res.get('protocol', "") == 'TCP':
            sql = "INSERT INTO tcp_event_detail (flow_id, ack, len, windows_size, hdr_len, checksum) VALUES (%s, %s, %s, %s, %s, %s);"
            sql_val = (hashed, res.get('tcp_ack'), res.get('tcp_len'), res.get('tcp_window_size'), res.get('tcp_hdr_len'), res.get('tcp_checksum'))
            debug_val = (hashed, str(res.get('tcp_ack', "")), str(res.get('tcp_len', "")), str(res.get('tcp_window_size', "")), str(res.get('tcp_hdr_len', "")), str(res.get('tcp_checksum', "")))
            self.dbq.put({'sql': sql, 'sql_val': sql_val, 'debug_val': debug_val})

            if res.get('src_port') == 502 or res.get('dest_port') == 502:
                sql = "INSERT INTO tcp_data (flow_id, ics_protocol_type, content) VALUES (%s, %s, %s);"
                sql_val = (hashed, 'modbus', res.get('tcp_content'))
                debug_val = (hashed, 'modbus', str(res.get('tcp_content', "")))
                self.dbq.put({'sql': sql, 'sql_val': sql_val, 'debug_val': debug_val})
            elif res.get('src_port') == 44818 or res.get('dest_port') == 44818:
                sql = "INSERT INTO tcp_data (flow_id, ics_protocol_type, content) VALUES (%s, %s, %s);"
                sql_val = (hashed, 'EtherNet/IP', res.get('tcp_content'))
                debug_val = (hashed, 'EtherNet/IP', str(res.get('tcp_content', "")))
                self.dbq.put({'sql': sql, 'sql_val': sql_val, 'debug_val': debug_val})


    def get_packet(self):
        while self.alive:
            pkt = self.lpu.get()
            self.parse_packet(pkt.get('packet_time'), pkt.get('raw_data'))

    def parse_ipv4(self, ipv4):
        res = {}
        res['len'] = ipv4.len
        res['offset'] = ipv4.offset
        res['ttl'] = ipv4.ttl
        res['src_ip'] = socket.inet_ntoa(ipv4.src)
        res['dst_ip'] = socket.inet_ntoa(ipv4.dst)
        src_port = ''
        dest_port = ''
        tcp_flags = ''
        protocol = ''
        if ipv4.p==dpkt.ip.IP_PROTO_TCP:

            res['protocol'] = 'TCP'
            tcp = ipv4.data

            res['tcp_flags'] = "{0:b}".format(tcp.flags)
            try:
                res['src_port'] = tcp.sport
                res['dest_port'] = tcp.dport
            except Exception as e:
                self.printer.error("Occur error " + str(e))

            res['tcp_hdr_len'] = tcp.__hdr_len__
            res['tcp_window_size'] = tcp.win
            res['tcp_ack'] = tcp.ack
            res['tcp_checksum'] = tcp.sum
            res['tcp_len'] = ipv4.len
            if tcp.sport == 502 or tcp.dport == 502 or tcp.sport == 44818 or tcp.dport == 44818:
                res['tcp_content'] = tcp.data

        elif ipv4.p==dpkt.ip.IP_PROTO_UDP:
            res['protocol'] = 'UDP'
            udp = ipv4.data
            try:
                res['src_port'] = udp.sport
                res['dest_port'] = udp.dport
            except Exception as e:
                self.printer.error("Occur error " + str(e))

        elif ipv4.p==dpkt.ip.IP_PROTO_IGMP:
            res['protocol'] = 'IGMP'
            igmp = ipv4.data

        elif ipv4.p==dpkt.ip.IP_PROTO_ICMP:
            res['protocol'] = 'ICMP'
            icmp = ipv4.data

        return res

    def parse_ipv6(self, ipv6):
        res = {}
        self.printer.debug('parse ipv6:', ipv6)
        res['len'] = ipv6.plen
        res['src_ip'] = socket.inet_ntop(socket.AF_INET6, ipv6.src)
        res['dst_ip'] = socket.inet_ntop(socket.AF_INET6, ipv6.dst)
        if ipv6.nxt==dpkt.ip.IP_PROTO_TCP:
            res['protocol'] = 'TCP'
            tcp = ipv6.data
            res['tcp_flags'] = "{0:b}".format(tcp.flags)
            res['src_port'] = tcp.sport
            res['dest_port'] = tcp.dport

        elif ipv6.nxt==dpkt.ip.IP_PROTO_UDP:
            res['protocol'] = 'UDP'
            udp = ipv6.data
            res['src_port'] = udp.sport
            res['dest_port'] = udp.dport

        elif ipv6.nxt==dpkt.ip.IP_PROTO_ICMP6:
            res['protocol'] = 'ICMPv6'
            icmp6 = ipv6.data

        elif ipv6.nxt==dpkt.ip.IP_PROTO_SCTP:
            res['protocol'] = 'SCTP'
            sctp = ipv6.data

        elif ipv6.nxt==dpkt.ip.IP_PROTO_HOPOPTS:
            res['protocol'] = 'HOPOPT'
            hop = ipv6.data

        else:
            res['protocol'] = 'SomethingWrong:'+str(ipv6.nxt)
            other = ipv6.data

        return res

    def parse_arp(self, arp):
        res = {}
        self.printer.debug('parse arp:', arp)
        self.printer.debug('arp.__hdr__: ', arp.__hdr__)
        self.printer.debug('arp.hrd: ', arp.hrd)
        self.printer.debug('arp.pro: ', arp.pro)
        self.printer.debug('arp.hln: ', arp.hln)
        self.printer.debug('arp.pln: ', arp.pln)
        self.printer.debug('arp.op: ', arp.op)
        self.printer.debug('arp.sha: ', arp.sha, 'conv: ', self.mac_addr(arp.sha))
        self.printer.debug('arp.spa: ', arp.spa, 'conv: ', socket.inet_ntoa(arp.spa))
        self.printer.debug('arp.tha: ', arp.tha, 'conv: ', self.mac_addr(arp.tha))
        self.printer.debug('arp.tpa: ', arp.tpa, 'conv: ', socket.inet_ntoa(arp.tpa))

        res['src_mac'] = self.mac_addr(arp.sha)
        res['dst_mac'] = self.mac_addr(arp.tha)
        res['src_ip'] = socket.inet_ntoa(arp.spa)
        res['dst_ip'] = socket.inet_ntoa(arp.tpa)

        return res

    def exit(self):
        self.alive = False