import socket, ssl, datetime, time, os, sys, select,queue as Queue
import chat_utils as chat_utils
from colorama import Fore, Style

# A class that implements the secure client 
class Chat_Client:
    # The IP address, port and address family of the server given during initialization
    def __init__(self,ip_addr,port,addr_family):
        new_socket = socket.socket(addr_family,socket.SOCK_STREAM)
        new_socket.connect((ip_addr,port))
        handshake_result = self.handle_chat_handshake(new_socket)
        if handshake_result != chat_utils.HANDSHAKE_FAILED:
            print(Fore.CYAN + Style.BRIGHT + 'Connected to the server! Type "CHAT_END" to end the  connection. \n')
            self.connection.setblocking(0)
            self.inputs = [sys.stdin, self.connection]
            self.outputs = []
            self.message_queue = Queue.Queue()
            self.fragment_list = []
            self.sent_message_number = 0
            self.recieved_message_number = 0
            self.lastline_type = 1
            while len(self.inputs) > 1:
                readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs)
                for s in readable:
                    if s is sys.stdin:
                        input_msg = s.readline()
                        input_msg = input_msg[:-1]
                        if input_msg.strip() != '':
                            self.sent_message_number += 1
                            if self.lastline_type == 1:
                                self.lastline_type = 0
                            self.message_queue.put(input_msg)
                            if self.connection not in self.outputs:
                                self.outputs.append(self.connection)
                    else:
                        try:
                            data = s.recv(4096).decode('UTF-8')
                            if data == chat_utils.CHAT_END:
                                print(Fore.RED + Style.BRIGHT + "\nServer ended the session! Closing the application!")
                                self.close_connection()
                            else:
                                if data[:12] == chat_utils.CHAT_MESSAGE:
                                    self.handle_new_message(data)
                        except ssl.SSLWantReadError:
                            continue
                for s in writable:
                    try:
                        next_msg = self.message_queue.get_nowait()
                    except Queue.Empty:
                        self.outputs.remove(s)
                    else:
                        if next_msg == chat_utils.CHAT_END:
                            s.send(next_msg.encode('UTF-8'))
                            print(Fore.RED + Style.BRIGHT + '\nClosing the connection!')
                            self.close_connection()
                        else:
                            msg_blocks = chat_utils.fragment(next_msg, self.sent_message_number)
                            for msg in msg_blocks:
                                s.send(msg)
                for s in exceptional:
                    if s == self.connection:
                        self.close_connection()
                        if handshake_result == chat_utils.HANDSHAKE_SUCESS_TLS:
                            new_socket.close()
        else:
            print(Fore.RED + Style.BRIGHT + "Oops... something went wrong! Connection failed. \n")

    def get_TLS_context(self):
        # creates a SSL context with all the necessary information
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations("./RootCA.crt")
        context.load_cert_chain(certfile="./alice.crt", keyfile="./alice.key")
        context.options = ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1 | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        return context

    def handle_chat_handshake(self, socket):
        input_str = chat_utils.CHAT_HELLO
        socket.sendall(input_str.encode('UTF-8'))
        resp = socket.recv(4096).decode('UTF-8')
        if resp == chat_utils.CHAT_REPLY:
            input_str = chat_utils.CHAT_STARTTLS
            socket.sendall(input_str.encode('UTF-8'))
            resp = socket.recv(4096).decode('UTF-8')
            if resp == chat_utils.CHAT_STARTTLS_ACK:
                context = self.get_TLS_context()
                secureSocket = context.wrap_socket(socket)
                serverCert = secureSocket.getpeercert(binary_form=True)
                if chat_utils.cert_checker(serverCert, ['./RootCA.crt']):
                    self.connection = secureSocket
                    return chat_utils.HANDSHAKE_SUCESS_TLS
                else:
                    input_str = chat_utils.CHAT_INVALID_CERTIFICATE
                    socket.sendall(input_str.encode('UTF-8'))
                    secureSocket.close()
                    socket.close()
            elif resp == chat_utils.CHAT_STARTTLS_NOT_SUPPORTED:
                self.connection = socket
                return chat_utils.HANDSHAKE_SUCESS_NO_TLS
            else:
                input_str = chat_utils.CHAT_INVALID_HANDSHAKE
                socket.sendall(input_str.encode('UTF-8'))
                socket.close()
        else:
            input_str = chat_utils.CHAT_INVALID_HANDSHAKE
            socket.sendall(input_str.encode('UTF-8'))
            socket.close()
        return chat_utils.HANDSHAKE_FAILED

    def handle_new_message(self,data):
        msg_num, num_fragments, fragment_num = chat_utils.get_message_details(data)
        if self.recieved_message_number != msg_num:
            self.recieved_message_number = msg_num
            if num_fragments == 1:
                if self.lastline_type == 1:
                    print("\033[A                             \033[A")
                else:
                    print("")
                    self.lastline_type = 1
                print(Fore.MAGENTA + Style.BRIGHT + "Bob says: ",Fore.GREEN + Style.BRIGHT + data[28:], Fore.CYAN + Style.BRIGHT +'\n')
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
                print(Fore.MAGENTA + Style.BRIGHT + "Bob says: ",Fore.GREEN + Style.BRIGHT + recieved_msg, Fore.CYAN + Style.BRIGHT +'\n')
                self.fragment_list.clear()
            else:
                self.fragment_list.append(data)

    def close_connection(self):
        if self.connection in self.outputs:
            self.outputs.remove(self.connection)
        self.inputs.remove(self.connection)
        self.connection.close()
        del self.message_queue