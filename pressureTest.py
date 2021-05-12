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
from typing import Tuple, Dict
from types import FunctionType

VERSION = "1.1.2"


def decode_n0(response_to_decode: bytes, head_len: int):
    """
        It decodes the result of the command N0 an prints the meaning of the returned output

        Parameters
        ___________
        response_to_decode: bytes
            The response returned by the payShield
        head_len: int
            The length of the header

        Returns
        ___________
        nothing
        """
    print("Message length", int.from_bytes(response_to_decode[:2], byteorder='big', signed=False))
    str_pointer = 2
    print("Header:", response_to_decode[str_pointer:str_pointer + head_len].decode('ascii', 'ignore'))
    str_pointer = str_pointer + head_len
    print("Command returned:", response_to_decode[str_pointer:str_pointer + 2].decode('ascii', 'ignore'))
    str_pointer = str_pointer + 2
    print("Error returned:", response_to_decode[str_pointer:str_pointer + 2].decode('ascii', 'ignore'))
    if (response_to_decode[str_pointer:str_pointer + 2]).decode('ascii', 'ignore') == '01':
        print("Invalid Random Value Length")
    elif (response_to_decode[str_pointer:str_pointer + 2]).decode('ascii', 'ignore') == '00':
        print("Random payload:(HEX)", binascii.hexlify(response_to_decode[6 + head_len:]).decode('ascii', 'ignore'))


def decode_no(response_to_decode: bytes, head_len: int):
    """
    It decodes the result of the command NO an prints the meaning of the returned output

    Parameters
    ___________
    response_to_decode: bytes
        The response returned by the payShield
    head_len: int
        The length of the header

    Returns
    ___________
    nothing
    """
    BUFFER_SIZE: Dict[str, str] = {
        '0': '2K bytes', '1': '8K bytes', '2': '16K bytes', '3': '32K bytes'}
    print("Message length", int.from_bytes(response_to_decode[:2], byteorder='big', signed=False))
    response_to_decode = response_to_decode.decode('ascii', 'replace')
    str_pointer: int = 2
    print("Header:", response_to_decode[str_pointer:str_pointer + head_len])
    str_pointer = str_pointer + head_len
    print("Command returned:", response_to_decode[str_pointer:str_pointer + 2])
    str_pointer = str_pointer + 2
    print("Error returned:", response_to_decode[str_pointer:str_pointer + 2])
    if response_to_decode[str_pointer:str_pointer + 2] == '00':
        str_pointer = str_pointer + 2
        print("I/O buffer size:", BUFFER_SIZE.get(response_to_decode[str_pointer:str_pointer + 1], "Unknown"))
        str_pointer = str_pointer + 1
        if response_to_decode[str_pointer:str_pointer + 1] == '0':
            print("Type of connection: UDP")
        elif response_to_decode[str_pointer:str_pointer + 1] == '1':
            print("Type of connection: TCP")
        else:
            print("Unexpected connection type")
        str_pointer = str_pointer + 1
        print("Number of TCP sockets:", response_to_decode[str_pointer:str_pointer + 2])
        str_pointer = str_pointer + 2
        print("Firmware number:", response_to_decode[str_pointer:str_pointer + 9])
        str_pointer = str_pointer + 9
        print("Reserved:", response_to_decode[str_pointer:str_pointer + 1])
        str_pointer = str_pointer + 1
        print("Reserved:", response_to_decode[str_pointer:str_pointer + 4])


def decode_nc(response_to_decode: bytes, head_len: int):
    """
    It decodes the result of the command NC an prints the meaning of the returned output
    The message trailer is not considered

    Parameters
    ___________
    response_to_decode: bytes
        The response returned by the payShield
    head_len: int
        The length of the header

    Returns
    ___________
    nothing
    """
    print("Message length", int.from_bytes(response_to_decode[:2], byteorder='big', signed=False))
    response_to_decode = response_to_decode.decode('ascii', 'replace')
    str_pointer: int = 2
    print("Header:", response_to_decode[str_pointer:str_pointer + head_len])
    str_pointer = str_pointer + head_len
    print("Command returned:", response_to_decode[str_pointer:str_pointer + 2])
    str_pointer = str_pointer + 2
    print("Error returned:", response_to_decode[str_pointer:str_pointer + 2])
    if response_to_decode[str_pointer:str_pointer + 2] == '00':
        str_pointer = str_pointer + 2
        print("LMK CRC:", response_to_decode[str_pointer:str_pointer + 16])
        str_pointer = str_pointer + 16
        print("Firmware number:", response_to_decode[str_pointer:str_pointer + 9])


def decode_j8(response_to_decode: bytes, head_len: int):
    """
    It decodes the result of the command J8 an prints the meaning of the returned output
    The message trailer is not considered

    Parameters
    ___________
    response_to_decode: bytes
        The response returned by the payShield
    head_len: int
        The length of the header

    Returns
    ___________
    nothing
    """
    print("Message length", int.from_bytes(response_to_decode[:2], byteorder='big', signed=False))
    response_to_decode = response_to_decode.decode('ascii', 'replace')
    str_pointer: int = 2
    print("Header: ", response_to_decode[str_pointer:str_pointer + head_len])
    str_pointer = str_pointer + head_len
    print("Command returned: ", response_to_decode[str_pointer:str_pointer + 2])
    str_pointer = str_pointer + 2
    print("Error returned: ", response_to_decode[str_pointer:str_pointer + 2])
    if response_to_decode[str_pointer:str_pointer + 2] == '00':
        str_pointer = str_pointer + 2
        print("Serial Number: ", response_to_decode[str_pointer:str_pointer + 12])
        str_pointer = str_pointer + 12
        print("Start Date: ", response_to_decode[str_pointer:str_pointer + 6])
        str_pointer = str_pointer + 6
        print("Start Time: ", response_to_decode[str_pointer:str_pointer + 6])
        str_pointer = str_pointer + 6
        print("End Date: ", response_to_decode[str_pointer:str_pointer + 6])
        str_pointer = str_pointer + 6
        print("End Time: ", response_to_decode[str_pointer:str_pointer + 6])
        str_pointer = str_pointer + 6
        print("Current Date: ", response_to_decode[str_pointer:str_pointer + 6])
        str_pointer = str_pointer + 6
        print("Current Time: ", response_to_decode[str_pointer:str_pointer + 6])
        str_pointer = str_pointer + 6
        print("Reboots: ", response_to_decode[str_pointer:str_pointer + 10])
        str_pointer = str_pointer + 10
        print("Tampers: ", response_to_decode[str_pointer:str_pointer + 10])
        str_pointer = str_pointer + 10
        print("Pin verifies/minute: ", response_to_decode[str_pointer:str_pointer + 7])
        str_pointer = str_pointer + 7
        print("Pin verifies/hour: ", response_to_decode[str_pointer:str_pointer + 5])
        str_pointer = str_pointer + 5
        print("Pin attacks: ", response_to_decode[str_pointer:str_pointer + 8])


def decode_j2(response_to_decode: bytes, head_len: int):
    """
    It decodes the result of the command J2 an prints the meaning of the returned output
    The message trailer is not considered

    Parameters
    ___________
    response_to_decode: bytes
        The response returned by the payShield
    head_len: int
        The length of the header

    Returns
    ___________
    nothing
    """
    msg_len = int.from_bytes(response_to_decode[:2], byteorder='big', signed=False)
    print("Message length", msg_len)
    response_to_decode = response_to_decode.decode('ascii', 'replace')
    str_pointer: int = 2
    print("Header: ", response_to_decode[str_pointer:str_pointer + head_len])
    str_pointer = str_pointer + head_len
    print("Command returned: ", response_to_decode[str_pointer:str_pointer + 2])
    str_pointer = str_pointer + 2
    print("Error returned: ", response_to_decode[str_pointer:str_pointer + 2])
    if response_to_decode[str_pointer:str_pointer + 2] == '00':
        str_pointer = str_pointer + 2
        print("Serial Number: ", response_to_decode[str_pointer:str_pointer + 12])
        str_pointer = str_pointer + 12
        print("Start Date: ", response_to_decode[str_pointer:str_pointer + 6])
        str_pointer = str_pointer + 6
        print("Start Time: ", response_to_decode[str_pointer:str_pointer + 6])
        str_pointer = str_pointer + 6
        print("End Date: ", response_to_decode[str_pointer:str_pointer + 6])
        str_pointer = str_pointer + 6
        print("End Time: ", response_to_decode[str_pointer:str_pointer + 6])
        str_pointer = str_pointer + 6
        print("Current Date: ", response_to_decode[str_pointer:str_pointer + 6])
        str_pointer = str_pointer + 6
        print("Current Time: ", response_to_decode[str_pointer:str_pointer + 6])
        str_pointer = str_pointer + 6
        print("Seconds: ", response_to_decode[str_pointer:str_pointer + 10])
        str_pointer = str_pointer + 10

        while (str_pointer + 15) <= msg_len:
            print("Starting percentage: ", response_to_decode[str_pointer:str_pointer + 3])
            str_pointer = str_pointer + 3
            print("Ending percentage: ", response_to_decode[str_pointer:str_pointer + 3])
            str_pointer = str_pointer + 3
            print("Number Times Periods: ", response_to_decode[str_pointer:str_pointer + 10])
            str_pointer = str_pointer + 10
            print("Delimiter: ", response_to_decode[str_pointer:str_pointer + 1])
            str_pointer = str_pointer + 1
        print("")


def decode_j4(response_to_decode: bytes, head_len: int):
    """
    It decodes the result of the command J4 an prints the meaning of the returned output
    The message trailer is not considered

    Parameters
    ___________
    response_to_decode: bytes
        The response returned by the payShield
    head_len: int
        The length of the header

    Returns
    ___________
    nothing
    """
    msg_len = int.from_bytes(response_to_decode[:2], byteorder='big', signed=False)
    print("Message length", msg_len)
    response_to_decode = response_to_decode.decode('ascii', 'replace')
    str_pointer: int = 2
    print("Header: ", response_to_decode[str_pointer:str_pointer + head_len])
    str_pointer = str_pointer + head_len
    print("Command returned: ", response_to_decode[str_pointer:str_pointer + 2])
    str_pointer = str_pointer + 2
    print("Error returned: ", response_to_decode[str_pointer:str_pointer + 2])
    if response_to_decode[str_pointer:str_pointer + 2] == '00':
        str_pointer = str_pointer + 2
        print("Serial Number: ", response_to_decode[str_pointer:str_pointer + 12])
        str_pointer = str_pointer + 12
        print("Start Date: ", response_to_decode[str_pointer:str_pointer + 6])
        str_pointer = str_pointer + 6
        print("Start Time: ", response_to_decode[str_pointer:str_pointer + 6])
        str_pointer = str_pointer + 6
        print("End Date: ", response_to_decode[str_pointer:str_pointer + 6])
        str_pointer = str_pointer + 6
        print("End Time: ", response_to_decode[str_pointer:str_pointer + 6])
        str_pointer = str_pointer + 6
        print("Current Date: ", response_to_decode[str_pointer:str_pointer + 6])
        str_pointer = str_pointer + 6
        print("Current Time: ", response_to_decode[str_pointer:str_pointer + 6])
        str_pointer = str_pointer + 6
        print("Seconds: ", response_to_decode[str_pointer:str_pointer + 10])
        str_pointer = str_pointer + 10

        while (str_pointer + 12) <= msg_len:
            print("Command Code: ", response_to_decode[str_pointer:str_pointer + 2])
            str_pointer = str_pointer + 2
            print("Transactions: ", response_to_decode[str_pointer:str_pointer + 12])
            str_pointer = str_pointer + 12
        print("")


def payshield_error_codes(error_code: str) -> str:
    """This function maps the result code with the error message.
        I derived the list of errors and messages from the following manual:
        payShield 10K Core Host Commands v1
        Revision: A
        Date: 04 August 2020
        Doc.Number: PUGD0537 - 004

        Parameters
        ----------
         error_code: str
            The status code returned from the payShield 10k

         Returns
         ----------
          a string containing the message of the error code
        """

    PAYSHIELD_ERROR_CODE = {
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

    return PAYSHIELD_ERROR_CODE.get(error_code, "Unknown error")


def check_returned_command_verb(result_returned: bytes, head_len: int, command_sent: str) -> Tuple[int, str, str]:
    """
    Checks if the command returned by the payShield is congruent to the command sent
    Parameters
    ----------
    result_returned: bytes
        The output returned from the payShield
    head_len: int
        The length of the header
    command_sent: str
        The command send to the payShield

    Returns
         ----------
        a Tuple[int, str, str]
        where the first value is 0 of the command is congruent or -1 if it is not
        the second value is the command sent
        the third value is the command returned by te payShield
    """

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


def run_test(ip_addr: str, port: int, host_command: str, proto: str = "tcp", header_len: int = 4,
             decoder_funct: FunctionType = None) -> int:
    """It connects to the specified host and port, using the specified protocol (tcp, udp or tls) and sends the command.
    
    Parameters
    ----------
     ip_addr: str
        The address to connect to. It can be an IP, hostname or FQDN
     port: int
        The port to connect to
     host_command: str
        The command to send to the payShield complete of the header part    
     proto: str
        The protocol to use, it can be usb, tcp or tls. If not specified the default is tcp
     header_len: int
        The length of the header. If not specified the value is 4 because it is the default factory value
        in payShield 10k
     decoder_funct: FunctionType
        If provided needs to be a reference to a function that is able to parse the command and print the meaning of it
        If not provided the default is None
     
     Returns
     ----------
      an integer value representing the error code: -1 means that some parameter were wrong.
    """

    # if proto != "tcp" and proto != "udp" and proto != "tls":
    if proto not in ['tcp', 'udp', 'tls']:
        print("invalid protocol parameter, It needs to be tcp, udp or tls")
        return -1

    try:

        # calculate the size and format it correctly
        size = pack('>h', len(host_command))

        # join everything together in python3
        message = size + host_command.encode()
        # Connect to the host and gather the reply in TCP or UDP
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
            print("sent data (ASCII) :", message[2:].decode("ascii", "ignore"))

        print("sent data (HEX) :", binascii.hexlify(message))

        if test_printable((data[2:]).decode("ascii", "ignore")):
            print("received data (ASCII):", data[2:].decode("ascii", "ignore"))

        print("received data (HEX) :", binascii.hexlify(data))
        if (decoder_funct is not None) and callable(decoder_funct):
            print("")
            print("-----DECODING RESPONSE-----")
            decoder_funct(data, header_len)

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
    print("This software is open source and it is under the Affero AGPL 3.0 license")
    print("")
    KEY_IGNORED_MSG = "If this option is specified --key is ignored"

    # List of decoder functions used to interpreter the result.
    # The reference to the function is used as parameter in the run_test function.
    # If the parameter is not passed because a decoder for that command it is not defined the default value of the
    # parameter assumes the value of None
    DECODERS = {
        'NO': decode_no,
        'NC': decode_nc,
        'N0': decode_n0,
        'J8': decode_j8,
        'J2': decode_j2,
        'J4': decode_j4
    }

    parser = argparse.ArgumentParser(description="Stress a PayShield appliance with RSA key generation")
    parser.add_argument("host", help="Ip address or hostname of the payShield")
    group = parser.add_mutually_exclusive_group()
    parser.add_argument("--port", "-p", help="The host port", default=1500, type=int)
    group.add_argument("--key", help="RSA key length. Accepted values are 2048 ot 4096",
                       default=2048, choices=[2048, 4096], type=int)
    group.add_argument("--nc", help="Just perform a NC test. " + KEY_IGNORED_MSG,
                       action="store_true")
    group.add_argument("--no", help="Retrieves HSM status information using NO command. " +
                                    KEY_IGNORED_MSG,
                       action="store_true")
    group.add_argument("--j2", help="Get HSM Loading using J2 command. " + KEY_IGNORED_MSG,
                       action="store_true")
    group.add_argument("--j4",
                       help="Get Host Command Volumes using J4 command. " + KEY_IGNORED_MSG,
                       action="store_true")
    group.add_argument("--j8",
                       help="Get Health Check Accumulated Counts using J8 command. " + KEY_IGNORED_MSG,
                       action="store_true")
    group.add_argument("--jk",
                       help="Get Instantaneous Health Check Status using JK command. " + KEY_IGNORED_MSG,
                       action="store_true")
    group.add_argument("--randgen",
                       help="Generate a random value 8 bytes long", action="store_true")
    parser.add_argument("--header",
                        help="the header string to prepend to the host command. If not specified the default is HEAD",
                        default="HEAD", type=str)
    parser.add_argument("--forever", help="if this option is specified the program runs for ever",
                        action="store_true")
    parser.add_argument("--decode", help="if this option is specified the reply of the payShield is interpreted "
                                         "if a decoder function for that command has been implemented",
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
    if args.no:
        command = args.header + 'NO00'
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
            if args.decode:
                run_test(args.host, args.port, command, args.proto, len(args.header),
                         DECODERS.get(command[len(args.header):len(args.header) + 2], None))
            else:
                run_test(args.host, args.port, command, args.proto, len(args.header), None)

            i = i + 1
            print("")
    else:
        for i in range(0, args.times):
            print("Iteration: ", i + 1, " of ", args.times)
            if args.decode:
                run_test(args.host, args.port, command, args.proto, len(args.header),
                         DECODERS.get(command[len(args.header):len(args.header) + 2], None))
            else:
                run_test(args.host, args.port, command, args.proto, len(args.header), None)
            print("")
        print("DONE")
