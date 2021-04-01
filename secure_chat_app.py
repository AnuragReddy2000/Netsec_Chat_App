#!/usr/bin/env python3

import sys, socket
from chat_client import Chat_Client
from chat_server import Chat_Server

def main():
    arg_len = len(sys.argv)
    if arg_len < 2:
        print("\nusage: \n \t -c <host> for clients, \n \t -s for server.")
    else:
        if sys.argv[1] == '-s':
            Chat_Server('::1', 8000, socket.AF_INET6)
        elif sys.argv[1] == '-c':
            if arg_len == 2:
                print("\nusage: \n \t -c <host> for clients, \n \t -s for server.")
            else:
                domain_name = sys.argv[2]
                addr_info = socket.getaddrinfo(domain_name,8000)
                addr_family = socket.AF_INET
                if len(addr_info[0][4]) == 4:
                    addr_family = socket.AF_INET6
                ip_addr = addr_info[0][4][0]
                Chat_Client(ip_addr,8000,addr_family)
        else:
            print("\nusage: \n \t -c <host> for clients, \n \t -s for server.")

main()