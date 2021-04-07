#!/usr/bin/env python3

import select, socket, sys, ssl, queue as Queue
import chat_utils as chat_utils
from colorama import Fore, Style

# A class that implements the chat server. The IP address, port and the address family are given during initialization 
class Chat_Server:
    def __init__(self,ip_addr,port,addr_family):
        self.server = socket.socket(addr_family, socket.SOCK_STREAM)
        self.server.bind((ip_addr, port))
        self.server.listen(5)
        print(Fore.GREEN + Style.BRIGHT + 'Server up and running! Waiting for client...\n')

        self.inputs = [sys.stdin]
        self.outputs = []
        self.message_queues = {}
        self.fragment_list = []
        self.sent_message_number = 0
        self.recieved_message_number = 0
        self.lastline_type = 1

        connection, client_address = self.server.accept()
        self.server.setblocking(0)
        handshake_result = self.handle_new_connection(connection)

        if handshake_result != chat_utils.HANDSHAKE_FAILED:
            print(Fore.CYAN + Style.BRIGHT + 'Connection accepted from client! Type "CHAT_CLOSE" to end the connection. \n')
        else:
            print(Fore.RED + Style.BRIGHT + "Handshake failed! Rejecting connection.",Style.RESET_ALL+'\n')
        while len(self.inputs) > 1:  
            readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs)
            for s in readable:
                if s is sys.stdin:
                    input_msg = s.readline()
                    input_msg = input_msg[:-1]
                    if input_msg.strip() != "":
                        if self.lastline_type == 1:
                            self.lastline_type = 0
                        self.sent_message_number += 1
                        self.message_queues[self.client].put(input_msg)
                        if self.client not in self.outputs:
                            self.outputs.append(self.client)
                else:
                    data = s.recv(4096).decode('UTF-8')
                    if data != chat_utils.CHAT_CLOSE:
                        if data[:12] == chat_utils.CHAT_MESSAGE:
                            self.handle_new_message(data)
                    else:
                        print(Fore.RED + Style.BRIGHT + "\nClient ended the session!", Style.RESET_ALL+'\n')
                        self.close_client_connection(s)
                        break
            for s in writable:
                try:
                    next_msg = self.message_queues[s].get_nowait()
                except Queue.Empty:
                    self.outputs.remove(s)
                else:
                    if next_msg == chat_utils.CHAT_CLOSE:
                        s.send(next_msg.encode('UTF-8'))
                        print(Fore.RED + Style.BRIGHT + '\nClosing the connection!', Style.RESET_ALL+'\n')
                        self.close_client_connection(s)
                        break
                    else:
                        msg_blocks = chat_utils.fragment(next_msg, self.sent_message_number)
                        for msg in msg_blocks:
                            s.send(msg)
            for s in exceptional:
                if s == self.client:
                    self.close_client_connection(s)
                    if handshake_result == chat_utils.HANDSHAKE_SUCESS_TLS:
                        connection.close()
        self.server.setblocking(1)

    def handle_new_connection(self, connection):
        incoming_msg = connection.recv(4096).decode('UTF-8')
        if incoming_msg == chat_utils.CHAT_HELLO:
            response_msg = chat_utils.CHAT_REPLY
            connection.sendall(response_msg.encode('UTF-8'))
            incoming_msg = connection.recv(4096).decode('UTF-8')
            if incoming_msg == chat_utils.CHAT_STARTTLS:
                response_msg = chat_utils.CHAT_STARTTLS_ACK
                connection.sendall(response_msg.encode('UTF-8'))
                secureClientSocket = ssl.wrap_socket(connection, 
                        server_side=True, 
                        ca_certs="./rootCA.crt", 
                        certfile="./bob.crt",
                        keyfile="./bob.key", 
                        cert_reqs=ssl.CERT_REQUIRED,
                        ssl_version=ssl.PROTOCOL_TLS)
                clientCert = secureClientSocket.getpeercert(binary_form=True)
                if chat_utils.cert_checker(clientCert, ['./rootCA.crt']):
                    incoming_msg = secureClientSocket.recv(4096).decode('UTF-8')
                    if incoming_msg == chat_utils.CHAT_HANDSHAKE_COMPLETED:
                        self.inputs.append(secureClientSocket)
                        self.message_queues[secureClientSocket] = Queue.Queue()
                        self.client = secureClientSocket
                        return chat_utils.HANDSHAKE_SUCESS_TLS
                    else:
                        response_msg = chat_utils.CHAT_INVALID_HANDSHAKE
                        connection.sendall(response_msg.encode('UTF-8'))
                        secureClientSocket.close()
                        connection.close()
                else:
                    response_msg = chat_utils.CHAT_INVALID_CERTIFICATE
                    connection.sendall(response_msg.encode('UTF-8'))
                    secureClientSocket.close()
                    connection.close()
            elif incoming_msg == chat_utils.CHAT_HANDSHAKE_COMPLETED:
                self.inputs.append(connection)
                self.message_queues[connection] = Queue.Queue()
                self.client = connection 
                return chat_utils.HANDSHAKE_SUCESS_NO_TLS
            else:
                response_msg = chat_utils.CHAT_INVALID_HANDSHAKE
                connection.sendall(response_msg.encode('UTF-8'))
                connection.close()
        else:
            response_msg = chat_utils.CHAT_INVALID_HANDSHAKE
            connection.sendall(response_msg.encode('UTF-8'))
            connection.close()
        return chat_utils.HANDSHAKE_FAILED

    def handle_new_message(self, data):
        msg_num, num_fragments, fragment_num = chat_utils.get_message_details(data)
        if self.recieved_message_number != msg_num:
            self.recieved_message_number = msg_num
            if num_fragments == 1:
                if self.lastline_type == 1:
                    print("\033[A                             \033[A")
                else:
                    print("")
                    self.lastline_type = 1
                print(Fore.MAGENTA + Style.BRIGHT  +"Alice says: ", Fore.GREEN + Style.BRIGHT + data[28:], Fore.CYAN + Style.BRIGHT + '\n')
            else:
                self.fragment_list.append(data)
        else:
            if num_fragments == fragment_num:
                self.fragment_list.append(data)
                recieved_msg = chat_utils.parse(self.fragment_list)
                if self.lastline_type == 1:
                    print("\033[A                             \033[A")
                else:
                    print("")
                    self.lastline_type = 1
                print(Fore.MAGENTA + Style.BRIGHT +'Alice says: ', Fore.GREEN + Style.BRIGHT + recieved_msg, Fore.CYAN + Style.BRIGHT + '\n')
                self.fragment_list.clear()
            else:
                self.fragment_list.append(data)

    def close_client_connection(self, client):
        if client in self.outputs:
            self.outputs.remove(client)
        self.inputs.remove(client)
        client.close()
        del self.message_queues[client]

def main():
    arg_len = len(sys.argv)
    if arg_len < 2:
        print("\nusage: \n \t -s")
    else:
        if sys.argv[1] == '-s':
            Chat_Server('::1', 8000, socket.AF_INET6)
        else:
            print("\nusage: \t -s")

main()