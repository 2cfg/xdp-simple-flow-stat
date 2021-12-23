from bcc import libbcc, table
import argparse
import ctypes
import ipaddress as ip
import time
from datetime import datetime
import psycopg2
from config import CONNECTION
import socket

class flow_t(ctypes.Structure):
  _fields_ = [("ip_src", ctypes.c_uint),
              ("ip_dst", ctypes.c_uint),
              ("src_port", ctypes.c_ushort),
              ("dst_port", ctypes.c_ushort),
              ("vlan_id", ctypes.c_ushort),
              ("protocol", ctypes.c_ubyte),
              ("fill1", ctypes.c_ubyte),
             ]


class counters_t(ctypes.Structure):
  _fields_ = [("total_bytes", ctypes.c_ulonglong),
              ("total_packets", ctypes.c_ulonglong),
             ]


class FlowTable(table.LruHash):
    def __init__(self, keytype, leaftype, max_entries, pinned_map):
        map_fd = libbcc.lib.bpf_obj_get(ctypes.c_char_p(pinned_map.encode('utf-8')))
        if map_fd < 0:
            raise ValueError("Failed to open eBPF map")

        self.map_fd = map_fd
        self.Key = keytype
        self.Leaf = leaftype
        self.max_entries = max_entries


def process_flow(flowtable, conn, hostname):
    
    commit_interval = 5000
    cursor = conn.cursor()
    commit_counter = 0
    while True:
        k = flowtable.next(key=None)

        if k is None:
            time.sleep(5)
            continue

        v = flowtable.__getitem__(k)
        try:
#            print("{}: {}:{}\t=> {}:{}  packets: {}\tbytes: {}".format(
#                k.protocol,
#                str(ip.IPv4Address(k.ip_src)).rjust(15),
#                str(k.src_port).ljust(5),
#                str(ip.IPv4Address(k.ip_dst)).rjust(15),
#                str(k.dst_port).ljust(5),
#                v.total_packets,
#                v.total_bytes
#            ))
            cursor.execute("INSERT INTO statistics (time, vlan_id, filter, proto, saddr, sport, daddr, dport, dsubnet, bytes, packets) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);",
                            (datetime.now(),
                             str(k.vlan_id),
                             str(hostname),
                             str(k.protocol),
                             str(ip.IPv4Address(k.ip_src)),
                             str(k.src_port),
                             str(ip.IPv4Address(k.ip_dst)),
                             str(k.dst_port),
                             str("0.0.0.0/0"),
                             str(v.total_bytes),
                             str(v.total_packets)
                    ))

        except (Exception, psycopg2.Error) as error:
            print(error)

        flowtable.__delitem__(k)
        commit_interval -= 1
        if commit_interval < 1:
            conn.commit()
            commit_interval = 5000
            commit_counter += 1
            print("{}\tcommit count: {}".format(datetime.now(), commit_counter))

    conn.commit()


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Flowstat')
    parser.add_argument('-d', '--dir', type=str, help='Traffic direction')
    args = parser.parse_args()


    if args.dir not in ('in', 'out'):
        print("Error. Wrong direction")
        exit(1)
    
    pinned_map = "/sys/fs/bpf/flowtable-{}".format(args.dir)

    flowtable = FlowTable(keytype=flow_t, leaftype=counters_t,  max_entries=33554432, pinned_map=pinned_map)

    hostname = socket.gethostname()

    with psycopg2.connect(CONNECTION) as conn:
        process_flow(flowtable, conn, hostname)
        
