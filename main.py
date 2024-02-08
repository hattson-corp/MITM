import socket
import time
import threading
import sys
import argparse
import hexdump # pip3 install simple-hexdump
class TCP_Proxy:
    def __init__(self):
        self.local_host = ""
        self.local_port = 0
        self.remote_host = ""
        self.remote_port = 0
        self.receive_first = False
    def server_loop(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            server.bind((self.local_host, self.local_port))
        except:
            print("[X] Failed to listen on port :",self.local_port,"\n[!] Try another port .")
            sys.exit(0)
        server.listen(5)

        while True :
            client_sock, addr = server.accept()

            print(f"[+] Received connection from {addr[0]}:{addr[1]}")

            proxy_thread = threading.Thread(target=self.proxy_handler, args=[client_sock,])
            proxy_thread.start()

    def request_handler(self, buffer):
        print(buffer)
        return buffer

    def response_handler(self, buffer):
        print(buffer)
        return buffer



    def hexdump(self, hex):
        print(hexdump.hexdump(hex))

    def receive_from(self, connection):
        buffer = ""

        connection.settimeout(2)

        try:
            while True :
                data = connection.recv(4096)
                if not data :
                    break
                buffer += data
        except:
            pass
        return buffer


    def main(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-l", "--localhost", help="Local host like 127.0.0.1 .", required=True, type=str)
        parser.add_argument("-p", "--localport", help="Local port like 1515 .", required=True, type=int)
        parser.add_argument("-r", "--remotehost", help="Remote host like 1.1.1.1 . ", required=True , type=str)
        parser.add_argument("-e", "--remoteport", help="Remote port like 1616", required=True, type=int)
        parser.add_argument("-f", "--recvfirst", help="use this option to set the program to listen first ", action="store_true")
        args = parser.parse_args()
        self.local_host = args.localhost
        self.local_port = args.localport
        self.remote_host = args.remotehost
        self.remote_port = args.remoteport
        self.receive_first = args.recvfirst

        self.server_loop()
    def proxy_handler(self, client_socket):
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((self.remote_host, self.remote_port))

        if self.receive_first:
            remote_buffer = self.receive_from(client_socket)
            self.hexdump(remote_buffer)
            remote_buffer = self.response_handler(remote_buffer)
            if len(remote_buffer):
                print(f"[<==] Sending {len(remote_buffer)} bytes to localhost ")
                client_socket.send(remote_buffer)
        while True :
            local_buffer = self.receive_from(client_socket)
            if len(local_buffer):
                print(f"[==>] Received {len(local_buffer)} from localhost ")
                self.hexdump(local_buffer)
                local_buffer = self.request_handler(local_buffer)

                remote_socket.send(local_buffer)
            remote_buffer = self.receive_from(remote_socket)
            if len (remote_buffer):
                print(f"[<==] Received {len(remote_buffer)} bytes from remote ")
                self.hexdump(remote_buffer)
                remote_buffer = self.response_handler(remote_buffer)
                client_socket.send(remote_buffer)
                print("[<==] Sent localhost ")
            if not len(local_buffer) or not len(remote_buffer):
                client_socket.close()
                remote_socket.close()
                print("[*] No more data . Closing the connections .")
                break
    def run(self):
        self.main()




class My_TCPProxy:
    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-l", "--localhost", help="Local host like 127.0.0.1 .", required=True, type=str)
        parser.add_argument("-p", "--localport", help="Local port like 1515 .", required=True, type=int)
        parser.add_argument("-r", "--remotehost", help="Remote host like 1.1.1.1 . ", required=True , type=str)
        parser.add_argument("-e", "--remoteport", help="Remote port like 1616", required=True, type=int)
        parser.add_argument("-f", "--recvfirst", help="use this option to set the program to listen first ", action="store_true")
        args = parser.parse_args()
        self.local_host = args.localhost
        self.local_port = args.localport
        self.remote_host = args.remotehost
        self.remote_port = args.remoteport
        self.receive_first = args.recvfirst


    def server_looop(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.bind((self.local_host, self.local_port))
        except:
            print("[X] Failed to listen to requested port . ")
            sys.exit(0)

        server.listen(10)
        while True:
            client_sock, addr = server.accept()
            print(f"[+] Client connected from {addr[0]}:{addr[1]}")
            thread_manager = threading.Thread(target=self.proxy_manager, args=[client_sock,])
            thread_manager.start()

    # def hexdump(self, bytes_input, width=16):
    #     current = 0
    #     end = len(bytes_input)
    #     result = ""
    #
    #     while current < end:
    #         byte_slice = bytes_input[current: current + width]
    #
    #         # hex section
    #         for b in byte_slice:
    #             result += "%02X " % b
    #
    #         # filler
    #         for _ in range(width - len(byte_slice)):
    #             result += " " * 3
    #         result += " " * 2
    #
    #         # printable character section
    #         for b in byte_slice:
    #             if (b >= 32) and (b < 127):
    #                 result += chr(b)
    #             else:
    #                 result += "."
    #
    #         result += "\n"
    #         current += width
    #
    #     return result

    # def hexdump(self, src, length=16):
    #     result = []
    #     digits = 4 if isinstance(src, bytes) else 2
    #     for i in range(0, len(src), length):
    #         s = src[i:i + length]
    #         hexa = b' '.join([f"{x:0{digits}X}" for x in s])
    #         text = b''.join([x if 0x20 <= x < 0x7F else b'.' for x in s])
    #         result.append(f"{i:04X} {hexa.decode('utf-8'): <{length * (digits + 1)}} {text.decode('utf-8')}")
    #     return '\n'.join(result)

    def hexdump(self, data, length=16):
        for i in range(0, len(data), length):
            chunk = data[i:i + length]
            hexa = ' '.join(f'{byte:02X}' for byte in chunk)
            text = ''.join(chr(byte) if 0x20 <= byte < 0x7F else '.' for byte in chunk)
            return f'{i:04X}   {hexa.ljust(length * 3)}   {text}'

    def proxy_manager(self, client):
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            remote.connect((self.remote_host, self.remote_port))
        except:
            print("[X] Problem connecting to the host .")
            sys.exit(0)
        # print("[+] Connected to remote successfully !")
        if self.receive_first:
            remote_buffer = self.rcv_from(remote)
            if len(remote_buffer):
                while True:
                    data = self.rcv_from(remote)
                    if data :
                        remote_buffer += data
                    if not data :
                        client.send(bytes(remote_buffer.encode()))
                        print("[*] Remote buffer :" ,self.hexdump(bytes(remote_buffer.encode())))
                        break
        while True :
            if not self.receive_first:
                remote_buffer = self.rcv_from(remote)
                if len(remote_buffer):
                    while True:
                        data = self.rcv_from(remote)
                        if data:
                            remote_buffer += data
                        if not data:
                            client.send(bytes(remote_buffer.encode()))
                            print("[*] Remote buffer :" ,self.hexdump(bytes(remote_buffer.encode())))
                            break
            local_buffer = self.rcv_from(client)
            if len(local_buffer):
                while True:
                    data = self.rcv_from(client)
                    if data:
                        local_buffer += data
                    if not data :
                        remote.send(bytes(local_buffer.encode()))
                        print("[*] Local buffer :" ,self.hexdump(bytes(local_buffer.encode())))
                        break
    def rcv_from(self, connection):
        buffer = b''
        connection.settimeout(2)
        try:
            while True:
                data = connection.recv(4096)
                if not data:
                    break
                buffer += data
        except:
            pass
        return buffer.decode()
    def run(self):
        self.server_looop()


test = My_TCPProxy()
test.run()