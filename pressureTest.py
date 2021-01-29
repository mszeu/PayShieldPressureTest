# payShield test utility by Marco S. Zuppone - msz@msz.eu
# This utility is released under AGPL 3.0 license
# please refer to the LICENSE file for more information about licensing
# and to README.md file for more information about the usage of it

import socket
import ssl
import binascii
import string
from struct import *
import argparse
from pathlib import Path
from typing import Tuple

VERSION = "1.0"


def payshield_error_codes(error_code: str) -> str:
    # This function maps the result code with the error message
    # I derived the list of errors and messages from the following manual:
    # payShield 10K Core Host Commands v1
    # Revision: A
    # Date: 04 August 2020
    # Doc.Number: PUGD0537 - 004

    pay_shield_error_table = {
        '00': 'No error',
        '01': 'Verification failure or warning of imported key parity error',
        '02': 'Key inappropriate length for algorithm',
        '04': 'Invalid key type code',
        '05': 'Invalid key length flag',
        '10': 'Source key parity error',
        '11': 'Destination key parity error or key all zeros',
        '12': 'Contents of user storage not available. Reset, power-down or overwrite',
        '13': 'Invalid LMK Identifier',
        '14': 'PIN encrypted under LMK pair 02-03 is invalid',
        '15': 'Invalid input data (invalid format, invalid characters, or not enough data provided)',
        '16': 'Console or printer not ready or not connected',
        '17': 'HSM not authorized, or operation prohibited by security settings',
        '18': 'Document format definition not loaded',
        '19': 'Specified Diebold Table is invalid',
        '20': 'PIN block does not contain valid values',
        '21': 'Invalid index value, or index/block count would cause an overflow condition',
        '22': 'Invalid account number',
        '23': 'Invalid PIN block format code. (Use includes where the security setting to implement PCI HSM '
              'limitations on PIN Block format usage is applied, and a Host command attempts to convert a PIN Block '
              'to a disallowed format.)',
        '24': 'PIN is fewer than 4 or more than 12 digits in length',
        '25': 'Decimalization Table error',
        '26': 'Invalid key scheme',
        '27': 'Incompatible key length',
        '28': 'Invalid key type',
        '29': 'Key function not permitted',
        '30': 'Invalid reference number',
        '31': 'Insufficient solicitation entries for batch',
        '32': 'AES not licensed',
        '33': 'LMK key change storage is corrupted',
        '39': 'Fraud detection',
        '40': 'Invalid checksum',
        '41': 'Internal hardware/software error: bad RAM, invalid error codes, etc.',
        '42': 'DES failure',
        '43': 'RSA Key Generation Failure',
        '46': 'Invalid tag for encrypted PIN',
        '47': 'Algorithm not licensed',
        '49': 'Private key error, report to supervisor',
        '51': 'Invalid message header',
        '65': 'Transaction Key Scheme set to None',
        '67': 'Command not licensed',
        '68': 'Command has been disabled',
        '69': 'PIN block format has been disabled',
        '74': 'Invalid digest info syntax (no hash mode only)',
        '75': 'Single length key masquerading as double or triple length key',
        '76': 'RSA public key length error or RSA encrypted data length error',
        '77': 'Clear data block error',
        '78': 'Private key length error',
        '79': 'Hash algorithm object identifier error',
        '80': 'Data length error. The amount of MAC data (or other data) is greater than or less than the expected '
              'amount.',
        '81': 'Invalid certificate header',
        '82': 'Invalid check value length',
        '83': 'Key block format error',
        '84': 'Key block check value error',
        '85': 'Invalid OAEP Mask Generation Function',
        '86': 'Invalid OAEP MGF Hash Function',
        '87': 'OAEP Parameter Error',
        '90': 'Data parity error in the request message received by the HSM',
        'A1': 'Incompatible LMK schemes',
        'A2': 'Incompatible LMK identifiers',
        'A3': 'Incompatible key block LMK identifiers',
        'A4': 'Key block authentication failure',
        'A5': 'Incompatible key length',
        'A6': 'Invalid key usage',
        'A7': 'Invalid algorithm',
        'A8': 'Invalid mode of use',
        'A9': 'Invalid key version number',
        'AA': 'Invalid export field',
        'AB': 'Invalid number of optional blocks',
        'AC': 'Optional header block error',
        'AD': 'Key status optional block error',
        'AE': 'Invalid start date/time',
        'AF': 'Invalid end date/time',
        'B0': 'Invalid encryption mode',
        'B1': 'Invalid authentication mode',
        'B2': 'Miscellaneous key block error',
        'B3': 'Invalid number of optional blocks',
        'B4': 'Optional block data error',
        'B5': 'Incompatible components',
        'B6': 'Incompatible key status optional blocks',
        'B7': 'Invalid change field',
        'B8': 'Invalid old value',
        'B9': 'Invalid new value',
        'BA': 'No key status block in the key block',
        'BB': 'Invalid wrapping key',
        'BC': 'Repeated optional block',
        'BD': 'Incompatible key types',
        'BE': 'Invalid key block header ID'}

    return pay_shield_error_table.get(error_code, "Unknown error")


def check_returned_command_verb(result_returned: bytes, head_len: int, command_sent: str) -> Tuple[int, str, str]:
    verb_returned = result_returned[2 + head_len:][:2]
    verb_sent = command_sent[head_len:][:2]
    verb_expected = verb_sent[0:1] + chr(ord(verb_sent[1:2]) + 1)
    if verb_returned != verb_expected.encode():
        return -1, verb_sent, verb_returned.decode()
    else:
        return 0, verb_sent, verb_returned.decode()


def check_return_message(result_returned: bytes, head_len: int) -> Tuple[str, str]:
    if len(result_returned) < 2 + head_len + 2:  # 2 bytes for len + 2 header len + 2 for command
        return "ZZ", "Incomplete message"
    # decode the first two bytes returned and transform them in integer
    try:
        expected_msg_len = int.from_bytes(result_returned[:2], byteorder='big', signed=False)
    except ValueError:
        return "ZZ", "Malformed message"
    except Exception:
        return "ZZ", "Unknown message length parsing error"

    # compares the effective message length with then one stated in the first two bytes of the message
    if len(result_returned) - 2 != expected_msg_len:
        return "ZZ", "Length mismatch"
    ret_code_position = 2 + head_len + 2

    # better be safe than sorry
    try:
        # ret_code = int(result_returned[ret_code_position:ret_code_position + 2])
        ret_code = result_returned[ret_code_position:ret_code_position + 2].decode()
    except (ValueError, UnicodeDecodeError):
        return "ZZ", "message result code parsing error"
    except Exception:
        return "ZZ", "Unknown message result code parsing error"

    # try to describe the error
    return ret_code, payshield_error_codes(ret_code)


def test_printable(input_str):
    return all(c in string.printable for c in input_str)


def run_test(ip_addr: str, port: int, host_command: str, proto: str = "tcp", header_len: int = 4) -> int:
    # it connects to the specified host and port, using the specified protocol that can me tcp, udp or tls and
    # sends the command.
    # The default header length is set to 4 if not provided because this is the out of box default value
    # in payShield 10k

    # if proto != "tcp" and proto != "udp" and proto != "tls":
    if proto not in ['tcp', 'udp', 'tls']:
        print("invalid protocol parameter, It needs to be tcp, udp or tls")
        return -1

    try:

        # calculate the size and format it correctly
        size = pack('>h', len(host_command))

        # join everything together in python3
        message = size + host_command.encode()
        # Connect to the host and gather the the reply in TCP or UDP
        buffer_size = 4096
        if proto == "tcp":
            # creates the TCP socket
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connection.connect((ip_addr, port))
            # send message
            connection.send(message)
            # receive data
            data = connection.recv(buffer_size)
        if proto == "tls":
            # creates the TCP TLS socket
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256:AES128-SHA256:HIGH:"
            ciphers += "!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK"
            ssl_sock = ssl.wrap_socket(connection, args.keyfile, args.crtfile)
            ssl_sock.connect((ip_addr, port))
            # send message
            ssl_sock.send(message)
            # receive data
            data = ssl_sock.recv(buffer_size)
        if proto == "udp":
            # create the UDP socket
            connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # send data
            connection.sendto(message, (ip_addr, port))
            # receive data
            data_tuple = connection.recvfrom(buffer_size)
            data = data_tuple[0]

        # try to decode the result code contained in the reply of the payShield
        check_result_tuple = (-1, "", "")
        return_code_tuple = check_return_message(data, header_len)
        if return_code_tuple[0] != "ZZ":
            print()
            check_result_tuple = check_returned_command_verb(data, header_len, host_command)

        print("Return code: " + str(return_code_tuple[0]) + " " + return_code_tuple[1])
        if check_result_tuple[0] != 0:
            print("NOTE: The response received from the HSM seems unrelated to the request!")

        print("Command sent/received: " + check_result_tuple[1] + " ==> " + check_result_tuple[2])

        # don't print ascii if msg or resp contains non printable chars
        if test_printable(message[2:].decode("ascii", "ignore")):
            print("sent data (ASCII) :", message[2:])

        print("sent data (HEX) :", binascii.hexlify(message))

        if test_printable((data[2:]).decode("ascii", "ignore")):
            print("received data (ASCII):", data[2:])

        print("received data (HEX) :", binascii.hexlify(data))

    except ConnectionError as e:
        print("Connection issue: ", e.message)
    except FileNotFoundError as e:
        print("The client certificate file or the client key file cannot be found or accessed.\n" +
              "Check value passed to the parameters --keyfile and --crtfile", e.message)
    except Exception as e:
        if hasattr(e, 'message'):
            print("Unexpected issue:", e.message)
        else:
            print("Unexpected issue:", e)

    finally:
        connection.close()


if __name__ == "__main__":
    print("PayShield stress utility, version " + VERSION + ", by Marco S. Zuppone - msz@msz.eu - https://msz.eu")
    print("To get more info about the usage invoke it with the -h option")
    print("This software is open source and it is under the Affero AGPL 3.0")
    print("")
    parser = argparse.ArgumentParser(description="Stress a PayShield appliance with RSA key generation")
    parser.add_argument("host", help="Ip address or hostname of the payShield")
    group = parser.add_mutually_exclusive_group()
    parser.add_argument("--port", "-p", help="The host port", default=1500, type=int)
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
                       help="Get Health Check Accumulated Counts using J8 command. "
                            "If this option is specified --key is ignored",
                       action="store_true")
    group.add_argument("--jk",
                       help="Get Instantaneous Health Check Status using JK command. "
                            "If this option is specified --key is ignored",
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
                        choices=["tcp", "udp", "tls"], type=str.lower)
    parser.add_argument("--keyfile", help="client key file, used if the protocol is TLS", type=Path,
                        default="client.key")
    parser.add_argument("--crtfile", help="client certificate file, used if the protocol is TLS", type=Path,
                        default="client.crt")
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
        command = args.header + 'N0008'
    if args.proto == 'tls':
        # check that the cert and key files are accessible
        if not (args.keyfile.exists() and args.crtfile.exists()):
            print("The client certificate file or the client key file cannot be found or accessed.\n" +
                  "Check value passed to the parameters --keyfile and --crtfile")
            print("You passed these values:")
            print("Certificate file:", args.crtfile)
            print("Key file:", args.keyfile)
            exit()
        if args.port < 2500:
            print("WARNING: generally the TLS base port is 2500. You are instead using the port ",
                  args.port, " please check that you passed the right value to the "
                             "--port parameter")

    if args.forever:
        i = 1
        while True:
            print("Iteration: ", i)
            run_test(args.host, args.port, command, args.proto, len(args.header))
            i = i + 1
            print("")
    else:
        for i in range(0, args.times):
            print("Iteration: ", i + 1, " of ", args.times)
            run_test(args.host, args.port, command, args.proto, len(args.header))
            print("")
        print("DONE")
