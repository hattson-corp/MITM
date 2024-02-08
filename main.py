import socket
import time
import threading
import sys
import argparse
from scapy.all import *
from scapy.utils import *
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
                        client.send(remote_buffer)
                        print("[*] Remote buffer :" ,self.hexdump(bytes(remote_buffer)))
                        break
        while True:
            remote_buffer = self.rcv_from(remote)
            if len(remote_buffer):
                data = self.rcv_from(remote)
                if data:
                    remote_buffer += data
                if not data:
                    client.send(remote_buffer)
                    print("[*] Remote buffer :" ,self.hexdump(remote_buffer))

            local_buffer = self.rcv_from(client)
            if len(local_buffer):
                data = self.rcv_from(client)
                if data:
                    local_buffer += data
                if not data :
                    remote.send(local_buffer)
                    print("[*] Local buffer :" ,self.hexdump(local_buffer))
                    
    def rcv_from(self, connection):
        buffer = b''
        connection.settimeout(3)
        try:
            while True:
                data = connection.recv(4096)
                if not data:
                    break
                buffer += data
        except:
            pass
        return buffer
    def run(self):
        self.server_looop()


# test = My_TCPProxy()
# test.run()

class TCP_Proxt_v_2:
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

    def server_loop(self):
        server_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            server_soc.bind((self.local_host, self.local_port))
            print(f"[*] Listening on local port  {self.local_port} ...")
        except:
            print(f"[X] Failed listening on local port {self.local_port} !")
            sys.exit(0)

        server_soc.listen(100)

        while True:
            client_soc, addr = server_soc.accept()

            print(f"[+] Incoming connected from {addr[0]}:{addr[1]}")
            tmp_thread = threading.Thread(target=self.proxy_handler, args=[client_soc,])
            tmp_thread.start()


    def proxy_handler(self, client_sock):
        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            remote_sock.connect((self.remote_host, self.remote_port))
        except:
            print(f"[X] Failed to connect to the remote host and prot {self.remote_host}:{self.remote_port}")
            sys.exit(0)

        while True:
            local_buffer = self.receive_from(client_sock)
            self.hexdump(local_buffer)
            if len(local_buffer):
                remote_sock.send(local_buffer)
            remote_buffer = self.receive_from(remote_sock)
            self.hexdump(remote_buffer)
            if len(remote_buffer):
                client_sock.send(remote_buffer)
            if not len(local_buffer) and not len(remote_buffer):
                print("[*] No data to transfer , terminating the connection ..")
                break


    def hexdump(self, data, length=16):
        for i in range(0, len(data), length):
            chunk = data[i:i + length]
            hexa = ' '.join(f'{byte:02X}' for byte in chunk)
            text = ''.join(chr(byte) if 0x20 <= byte < 0x7F else '.' for byte in chunk)
            out = open("outfile.txt", "a+")
            out.write(f"{i:04X}   {hexa.ljust(length * 3)}   {text}\n")
            print(f'{i:04X}   {hexa.ljust(length * 3)}   {text}')

    def receive_from(self, connection):
        data = b''
        connection.settimeout(2)

        try:
            while True:
                buffer = connection.recv(4096)
                if not len(buffer):
                    break
                data += buffer
        except:
            pass
        return data
    def run(self):
        self.server_loop()
v2 = TCP_Proxt_v_2()
v2.run()
