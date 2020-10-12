# payShield test utility by Marco S. Zuppone - msz@msz.eu
# This utility is released under AGPL 3.0 license
# please refer to the LICENSE file for more information about licensing
# and to README.md file for more information about the usage of it

import socket
import binascii
import string
from struct import *
import argparse


def check_return_message(result_returned, head_len):
    if len(result_returned) < 2 + head_len + 2:  # 2 bytes for len + 2 header len + 2 for command
        return -1, "Incomplete message"
    # decode the first two bytes returned and transform them in integer
    try:
        expected_msg_len = int.from_bytes(result_returned[:2], byteorder='big', signed=False)
    except ValueError:
        return -99, "Malformed message"
    except Exception:
        return -100, "Unknown message length parsing error"

    # compares the effective message length with then one stated in the first two bytes of the message
    if len(result_returned) - 2 != expected_msg_len:
        return -2, "Len mismatch"
    ret_code_position = 2 + head_len + 2

    # better be safe than sorry
    try:
        ret_code = int(result_returned[ret_code_position:ret_code_position + 2])
    except ValueError:
        return -102, "message result code parsing error"
    except Exception:
        return -101, "Unknown message result code parsing error"

    # try to describe the error

    if ret_code == 0:
        return 0, "OK"
    elif ret_code == 17:
        return ret_code, "HSM not authorized, or operation prohibited by security settings"
    elif ret_code == 3:
        return ret_code, "Invalid public key encoding type"
    elif ret_code == 4:
        return ret_code, "Key Length error"
    elif ret_code == 5:
        return ret_code, "Invalid key type"
    elif ret_code == 6:
        return ret_code, "Public exponent length error"
    elif ret_code == 8:
        return ret_code, "Supplied public exponent is even"
    elif ret_code == 47:
        return ret_code, "Algorithm not licensed"
    elif ret_code == 48:
        return ret_code, "Stronger LMK required to protect this size RSA key"
    elif ret_code == 68:
        return ret_code, "Command disabled"
    else:
        return ret_code, "Error returned"  # if the error message is not in the list


def test_printable(input_str):
    return all(c in string.printable for c in input_str)


def run_test(ip_addr, port, host_command, proto="tcp"):
    if proto != "tcp" and proto != "udp":
        print("invalid protocol parameter, It needs to be tcp or udp")
        return -1

    try:

        # calculate the size and format it correctly
        size = pack('>h', len(host_command))
        # join everything together in python3

        message = size + host_command.encode()
        # Connect to the host and the the reply in TCP or UDP
        buffer_size = 4096
        if proto == "tcp":
            # creates the TCP socket
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connection.connect((ip_addr, port))
            # send message
            connection.send(message)
            # receive data
            data = connection.recv(buffer_size)
        else:
            # create the UDP socket
            connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # send data
            connection.sendto(message, (ip_addr, port))
            # receive data
            data_tuple = connection.recvfrom(buffer_size)
            data = data_tuple[0]

        # try to decode the result code contained in the reply of the payShield
        return_code_tuple = check_return_message(data, len(args.header))
        print("Return code: " + str(return_code_tuple[0]) + " " + return_code_tuple[1])

        # don't print ascii if msg or resp contains non printable chars
        if test_printable(message[2:].decode("ascii", "ignore")):
            print("sent data (ASCII) :", message[2:])

        print("sent data (HEX) :", binascii.hexlify(message))

        if test_printable((data[2:]).decode("ascii", "ignore")):
            print("received data (ASCII):", data[2:])

        print("received data (HEX) :", binascii.hexlify(data))

    except ConnectionError as e:
        print("Connection issue: ", e.strerror)
    except Exception:
        print("Unexpected issue:")
    finally:
        connection.close()


if __name__ == "__main__":
    print("PayShield stress utility by Marco S. Zuppone - msz@msz.eu")
    print("To get more info about the usage invoke it with the -h option")
    print("This software is open source and it is under the Affero AGPL 3.0")
    print("")
    parser = argparse.ArgumentParser(description="Stress a PayShield appliance with RSA key generation")
    parser.add_argument("host", help="Ip address or hostname of the payShiled")
    group = parser.add_mutually_exclusive_group()
    parser.add_argument("--port", "-p", help="The host port", default=1500)
    group.add_argument("--key", help="RSA key length. Accepted values are 2048 ot 4096",
                       default=2048, choices=[2048, 4096], type=int)
    group.add_argument("--nc", help="Just perform a NC test If this option is specified --key is ignored",
                       action="store_true")
    group.add_argument("--j2", help="Get HSM Loading using J2 command. If this option is specified --key is ignored",
                       action="store_true")
    group.add_argument("--j4",
                       help="Get Host Command Volumes using J4 command. If this option is specified --key is ignored",
                       action="store_true")
    group.add_argument("--j8",
                       help="Get Health Check Accumulated Counts using J8 command. If this option is specified --key is ignored",
                       action="store_true")
    group.add_argument("--jk",
                       help="Get Instantaneous Health Check Status using JK command. If this option is specified --key is ignored",
                       action="store_true")
    group.add_argument("--randgen",
                       help="Generate a random value 8 bytes long", action="store_true")
    parser.add_argument("--header",
                        help="the header string to prepend to the host command. If not specified the default is HEAD",
                        default="HEAD", type=str)
    parser.add_argument("--forever", help="if this option is specified the program will run for ever",
                        action="store_true")
    parser.add_argument("--times", help="how many time to repeat the operation", type=int, default=1000)
    parser.add_argument("--proto", help="accepted value are tcp or udp, the default is tcp", default="tcp",
                        choices=["tcp", "udp"], type=str)

    args = parser.parse_args()
    # the order of the IF here is important due to the default arguments
    if args.key == 2048:
        command = args.header + 'EI2204801#0000'
    else:
        command = args.header + 'EI2409601#0000'
    if args.nc:
        command = args.header + 'NC'
    if args.j2:
        command = args.header + 'J2'
    if args.j4:
        command = args.header + 'J4'
    if args.j8:
        command = args.header + 'J8'
    if args.jk:
        command = args.header + 'JK'
    if args.randgen:
        command = args.header + 'N0064'
    if args.forever:
        while True:
            run_test(args.host, args.port, command, args.proto)
            print("")
    else:
        for i in range(0, args.times):
            run_test(args.host, args.port, command, args.proto)
            print("Iteration: ", i + 1)
            print("")
