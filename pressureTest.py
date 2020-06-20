import socket
import binascii
import string
from struct import *
import argparse


def test_printable(str):
    return all(c in string.printable for c in str)


def build_command(command):
    # convert hex supplied data into binary
    host_command = ''
    i = 0
    while True:
        if command[i:i + 1] == '<':
            i = i + 1
            while True:
                host_command = host_command + binascii.a2b_hex(command[i:i + 2])
                i = i + 2
                if command[i:i + 1] == '>':
                    i = i + 1
                    break
        else:
            host_command = host_command + command[i]
            i = i + 1

        if i == len(command):
            break
    return host_command


def run_test(tcp_ip, tcp_port, host_command):
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.connect((tcp_ip, tcp_port))
    buffer_size = 1024

    # Convert hex to binary
    host_command = build_command(host_command)
    # calculate the size and format it correctly
    size = pack('>h', len(host_command))
    # join everything together
    message = size + host_command
    # send message
    connection.send(message)
    # receive data
    data = connection.recv(buffer_size)
    # don't print ascii if msg or resp contains non printable chars
    if test_printable(message[2:]):
        print("sent data (ASCII) :", message[2:])
    print("sent data (HEX) :", message.encode('hex'))
    if test_printable(data[2:]):
        print("received data (ASCII):", data[2:])
    print("received data (HEX) :", data.encode('hex'))
    connection.close()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Stress a PayShield appliance with RSA key generation")
    parser.add_argument("--host", "-ip", help="Ip address or hostname of the payShiled")
    parser.add_argument("--port", "-p", help="The host port", default=1500)
    parser.add_argument("--key", help="RSA key length. Accepted values are 2048 ot 4096",
                        default=2048, choices=[2048, 4096], type=int)
    parser.add_argument("--forever", help="if this option is specified the program will run for ever",
                        action="store_true")
    parser.add_argument("--times", help="how many time to repeat the operation", type=int, default=1000)
    args = parser.parse_args()
    if args.key == 2048:
        command = 'HEADEI2204801%00#0000'
    else:
        command = 'HEADEI2409601%00#0000'
    if args.forever:
        while 1 == 1:
            run_test(args.host, args.port, command)
    else:
        for i in range(0, args.times):
            run_test(args.host, args.port, command)
