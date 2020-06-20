import binascii
import socket
import string
from struct import *

TCP_IP = "192.168.0.36"
TCP_PORT = 1500
COMMAND = 'HEADNC'


def test_printable(str):
    return all(c in string.printable for c in str)


def build_command(command):
    # convert hex supplied data into binary
    h_command = ''
    i = 0
    while True:
        if command[i:i + 1] == '<':
            i = i + 1
            while True:
                h_command = h_command + binascii.a2b_hex(command[i:i + 2])
                i = i + 2
                if command[i:i + 1] == '>':
                    i = i + 1
                    break
        else:
            h_command = h_command + command[i]
            i = i + 1

        if i == len(command):
            break
    return h_command


def main():
    global TCP_IP
    global TCP_PORT
    global COMMAND
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.connect((TCP_IP, TCP_PORT))
    BUFFER_SIZE = 1024

    # Convert hex to binary
    COMMAND = build_command(COMMAND)
    # calculate the size and format it correctly
    SIZE = pack('>h', len(COMMAND))
    # join everything together
    MESSAGE = SIZE + COMMAND
    # send MESSAGE
    connection.send(MESSAGE)
    # receive data
    data = connection.recv(BUFFER_SIZE)
    # don't print ascii if msg or resp contain non printable chars
    if test_printable(MESSAGE[2:]):
        print("sent data (ASCII) :", MESSAGE[2:])
    print("sent data (HEX) :", MESSAGE.encode('hex'))
    if test_printable(data[2:]):
        print("received data (ASCII):", data[2:])
    print("received data (HEX) :", data.encode('hex'))
    connection.close()


if __name__ == "__main__":
    while 1 == 1:
        main()
