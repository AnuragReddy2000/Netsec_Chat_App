
import select, socket, sys, datetime, ssl, queue as Queue
import chat_utils as chat_utils

# A class that implements the chat server. The IP address, port and the address family are given during initialization 
class Chat_Server:
    def __init__(self,ip_addr,port,addr_family):
        self.server = socket.socket(addr_family, socket.SOCK_STREAM)
        self.server.bind((ip_addr, port))
        self.server.listen(5)

        self.inputs = [sys.stdin]
        self.outputs = []
        self.message_queues = {}

        while True:
            connection, client_address = self.server.accept()
            
            handshake_result = self.handle_new_connection(connection)
            if handshake_result != chat_utils.HANDSHAKE_FAILED:
                print('Connection accepted from client! Type "CHAT_END" to end the connection. \n')
            while len(self.inputs) > 1:  
                readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs)
                for s in readable:
                    if s is sys.stdin:
                        input_msg = s.readline()
                        input_msg = input_msg[:-1]
                        if input_msg.strip() != "":
                            print("")
                            self.message_queues[self.client].put(input_msg)
                            if self.client not in self.outputs:
                                self.outputs.append(self.client)
                    else:
                        data = s.recv(4096).decode('UTF-8')
                        #recv_time = datetime.datetime.now()
                        if data != chat_utils.CHAT_END:
                            print("The client says: ",data, '\n')
                            #handle incoming message
                        else:
                            if s in self.outputs:
                                self.outputs.remove(s)
                            self.inputs.remove(s)
                            print("Client ended the session!")
                            s.close()
                            del self.message_queues[s]
                            break

                for s in writable:
                    try:
                        next_msg = self.message_queues[s].get_nowait()
                    except Queue.Empty:
                        self.outputs.remove(s)
                    else:
                        s.send(next_msg.encode('UTF-8'))
                        if next_msg == chat_utils.CHAT_END:
                            print('Closing the connection!')
                            if s in self.outputs:
                                self.outputs.remove(s)
                            self.inputs.remove(s)
                            s.close()
                            del self.message_queues[s]
                            break

                for s in exceptional:
                    if s == self.client:
                        self.inputs.remove(self.client)
                        if self.client in self.outputs:
                            self.outputs.remove(self.client)
                        self.client.close()
                        if handshake_result == chat_utils.HANDSHAKE_SUCESS_TLS:
                            connection.close()
                        del self.message_queues[self.client]
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
                        ca_certs="./RootCA.pem", 
                        certfile="./RootCA.crt",
                        keyfile="./RootCA.key", 
                        cert_reqs=ssl.CERT_REQUIRED,
                        ssl_version=ssl.PROTOCOL_TLS)
                clientCert = secureClientSocket.getpeercert()
                if True: # cert valid
                    self.inputs.append(secureClientSocket)
                    self.message_queues[secureClientSocket] = Queue.Queue()
                    self.client = secureClientSocket
                    return chat_utils.HANDSHAKE_SUCESS_TLS
                else:
                    response_msg = chat_utils.CHAT_INVALID_CERTIFICATE
                    connection.sendall(response_msg.encode('UTF-8'))
                    secureClientSocket.close()
                    connection.close()
            else:
                self.inputs.append(connection)
                self.message_queues[connection] = Queue.Queue()
                self.client = connection 
                return chat_utils.HANDSHAKE_SUCESS_NO_TLS
                #Handle the message
        else:
            response_msg = chat_utils.CHAT_INVALID_HANDSHAKE
            connection.sendall(response_msg.encode('UTF-8'))
            connection.close()
        return chat_utils.HANDSHAKE_FAILED

def main():
    # command line arguments
    arg_len = len(sys.argv)
    args = sys.argv
    if len(sys.argv) < 3:
        print("usage:", sys.argv[0], "<host> <port>")
        sys.exit(1)
    addr_family = socket.AF_INET
    ip_addr = args[1]
    # Determining the address family from the IP address provided
    if ip_addr.count(":") != 0:
        addr_family = socket.AF_INET6
    Chat_Server(args[1],int(args[2]),addr_family)

main()
