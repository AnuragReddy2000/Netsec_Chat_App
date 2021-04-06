#!/usr/bin/env python3

import sys, socket
from downgrade import Downgrade_Server


def main():
    arg_len = len(sys.argv)
    if arg_len < 4:
        print("\nusage: \n \t -d <server> <client> for downgrade attack, \n \t -m <server> <client> for Active MITM attack.")
    else:
        server = sys.argv[2]
        server_addr_info = socket.getaddrinfo(server, 8000)
        server_ip = server_addr_info[0][4][0]
        client = sys.argv[3]
        client_addr_info = socket.getaddrinfo(client, 8000)
        client_ip = client_addr_info[0][4][0]
        if sys.argv[1] == '-d':
            Downgrade_Server('172.31.0.4',server_ip, client_ip)
        elif sys.argv[1] == '-m':
            print("Active MITM not yet implemented.")
        else:
            print("\nusage: \n \t -d <server> <client> for downgrade attack, \n \t -m <server> <client> for Active MITM attack.")

main()