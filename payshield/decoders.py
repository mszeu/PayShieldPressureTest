# payShield test utility by Marco S. Zuppone - msz@msz.eu
# Project name: payShieldPressureTest
# Official GitHub Repository: https://github.com/mszeu/PayShieldPressureTest
# Copyright (C) 2020-2026 by Marco S. Zuppone - msz@msz.eu
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
decoders.py
-----------
Functions that parse and pretty-print the raw responses returned by the
payShield 10K host port for each supported command.

Each ``decode_*`` function receives the raw ``bytes`` response and the
integer header length, then prints the interpreted fields to stdout.

The ``DECODERS`` dictionary maps the two-character command verb (e.g. ``'NC'``)
to the matching decoder function so callers can perform a simple lookup.
"""

import socket
from struct import pack
from typing import Dict, Tuple


# No internal imports needed: decoders is a leaf module within the package.


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def hex2ip(hex_ip: str) -> str:
    """Convert an 8-character hex string to a dotted-decimal IPv4 address.

    Parameters
    ----------
    hex_ip : str
        Eight hexadecimal characters representing a 32-bit IPv4 address.

    Returns
    -------
    str
        Dotted-decimal representation, e.g. ``'192.168.1.1'``.
    """
    addr_long = int(hex_ip, 16)
    return socket.inet_ntoa(pack(">L", addr_long))


def common_parser(response_to_decode: bytes, head_len: int) -> Tuple[str, int, int]:
    """Parse the fixed-format prefix shared by all payShield responses.

    Decodes the raw bytes, prints the message length, header, command verb,
    and error code, then returns the values needed by command-specific
    decoders.

    Parameters
    ----------
    response_to_decode : bytes
        The raw response returned by the payShield.
    head_len : int
        The length of the message header (typically 4).

    Returns
    -------
    message_str : str
        The response decoded as ASCII (with replacement for non-ASCII bytes).
    msg_len : int
        The message length as declared in the first two bytes.
    str_pointer : int
        The index of the first byte after the error-code field, i.e. where
        command-specific payload begins.
    """
    msg_len = int.from_bytes(response_to_decode[:2], byteorder='big', signed=False)
    print("Message length: ", msg_len)
    response_str = response_to_decode.decode('ascii', 'replace')
    str_pointer: int = 2
    print("Header: ", response_str[str_pointer:str_pointer + head_len])
    str_pointer += head_len
    print("Command returned: ", response_str[str_pointer:str_pointer + 2])
    str_pointer += 2
    print("Error returned: ", response_str[str_pointer:str_pointer + 2])
    return response_str, msg_len, str_pointer


# ---------------------------------------------------------------------------
# Command decoders
# ---------------------------------------------------------------------------

def decode_n0(response_to_decode: bytes, head_len: int) -> None:
    """Decode and print the response to the N0 (Generate Random) command.

    Parameters
    ----------
    response_to_decode : bytes
        Raw response from the payShield.
    head_len : int
        Length of the message header.
    """
    response_str, msg_len, str_pointer = common_parser(response_to_decode, head_len)
    if response_str[str_pointer:str_pointer + 2] == '01':
        print("Invalid Random Value Length")
    elif response_str[str_pointer:str_pointer + 2] == '00':
        print("Random payload:(HEX)", bytes.hex(response_to_decode[6 + head_len:]))


def decode_no(response_to_decode: bytes, head_len: int) -> None:
    """Decode and print the response to the NO (HSM Status) command.

    Parameters
    ----------
    response_to_decode : bytes
        Raw response from the payShield.
    head_len : int
        Length of the message header.
    """
    BUFFER_SIZE: Dict[str, str] = {
        '0': '2K bytes', '1': '8K bytes', '2': '16K bytes', '3': '32K bytes',
    }
    NET_PROTO: Dict[str, str] = {'0': 'UDP', '1': 'TCP'}

    response_str, msg_len, str_pointer = common_parser(response_to_decode, head_len)
    if response_str[str_pointer:str_pointer + 2] == '00':  # No errors
        if len(response_str) >= (24 + head_len):  # Mode 00
            str_pointer += 2
            print("I/O buffer size: ", BUFFER_SIZE.get(response_str[str_pointer:str_pointer + 1], "Unknown"))
            str_pointer += 1
            print("Type of connection: ", NET_PROTO.get(response_str[str_pointer:str_pointer + 1], "Unknown"))
            str_pointer += 1
            # From FW 1.8a the Number of TCP sockets field grew from 2 to 4 characters
            socket_field_len = 4 if len(response_str) > (24 + head_len) else 2
            print("Number of TCP sockets: ", response_str[str_pointer:str_pointer + socket_field_len])
            str_pointer += socket_field_len
            print("Firmware number: ", response_str[str_pointer:str_pointer + 9])
            str_pointer += 9
            print("Reserved: ", response_str[str_pointer:str_pointer + 1])
            str_pointer += 1
            print("Reserved: ", response_str[str_pointer:str_pointer + 4])

        else:  # Mode 01
            str_pointer += 2
            pci_flag = response_str[str_pointer:str_pointer + 1]
            if pci_flag == '0':
                print(
                    "Some of the security settings relevant to PCI HSM compliance have non-compliant values.\n"
                    "\"The Enforce key type 002 separation for PCI HSM compliance\" setting is one of these."
                )
            elif pci_flag == '1':
                print("All security settings relevant to PCI HSM compliance have compliant values.")
            elif pci_flag == '2':
                print(
                    "Some of the security settings relevant to PCI HSM compliance have non-compliant values.\n"
                    "\"The Enforce key type 002 separation for PCI HSM compliance\" setting is not one of these."
                )


def decode_ni(response_to_decode: bytes, head_len: int) -> None:
    """Decode and print the response to the NI (Ethernet Host Port Info) command.

    Parameters
    ----------
    response_to_decode : bytes
        Raw response from the payShield.
    head_len : int
        Length of the message header.
    """
    NET_PROTO: Dict[str, str] = {'0': 'TCP', '1': 'UDP'}
    SPECIFIC_ERROR: Dict[str, str] = {
        '01': 'Failed to execute NETSTAT',
        '82': 'Invalid Ethernet Statistics value',
    }
    NET_CONNECTION_STATUS: Dict[str, str] = {'0': 'ESTABLISHED', '1': 'CLOSED'}

    response_str, msg_len, str_pointer = common_parser(response_to_decode, head_len)
    if response_str[str_pointer:str_pointer + 2] == '00':
        str_pointer += 2
        records_to_follow = int(response_str[str_pointer:str_pointer + 4])
        print("Records to follow: ", records_to_follow)
        str_pointer += 4
        for _ in range(records_to_follow):
            print("Protocol: ", NET_PROTO.get(response_str[str_pointer:str_pointer + 1], "Unknown"))
            str_pointer += 1
            print("Local port number: ", response_str[str_pointer:str_pointer + 4])
            str_pointer += 4
            print("IP Address: ", hex2ip(response_str[str_pointer:str_pointer + 8]))
            str_pointer += 8
            print("Remote port number: ", response_str[str_pointer:str_pointer + 4])
            str_pointer += 4
            print("Connection Status: ",
                  NET_CONNECTION_STATUS.get(response_str[str_pointer:str_pointer + 1], 'Reserved'))
            str_pointer += 1
            print("Duration: ", response_str[str_pointer:str_pointer + 8])
            str_pointer += 8
        print("Total Bytes Sent: ", int(response_str[str_pointer:str_pointer + 16], 16))
        str_pointer += 16
        print("Total Bytes Received: ", int(response_str[str_pointer:str_pointer + 16], 16))
        str_pointer += 16
        print("Total Unicast Packets Sent: ", int(response_str[str_pointer:str_pointer + 8], 16))
        str_pointer += 8
        print("Total Unicast Packets Received: ", int(response_str[str_pointer:str_pointer + 8], 16))
        str_pointer += 8
        print("Total Non-unicast packets Sent: ", int(response_str[str_pointer:str_pointer + 8], 16))
        str_pointer += 8
        print("Total Non-unicast packets Received: ", int(response_str[str_pointer:str_pointer + 8], 16))
        str_pointer += 8
        print("Total Packets Discarded During Send: ", int(response_str[str_pointer:str_pointer + 8], 16))
        str_pointer += 8
        print("Total Packets Discarded During Receive: ", int(response_str[str_pointer:str_pointer + 8], 16))
        str_pointer += 8
        print("Total Errors During Send: ", int(response_str[str_pointer:str_pointer + 8], 16))
        str_pointer += 8
        print("Total Errors During Receive: ", int(response_str[str_pointer:str_pointer + 8], 16))
        str_pointer += 8
        print("Total Unknown Packets: ", int(response_str[str_pointer:str_pointer + 8], 16))
    else:
        specific = SPECIFIC_ERROR.get(response_str[str_pointer:str_pointer + 2])
        if specific is not None:
            print("Command specific error: ", specific)


def decode_nc(response_to_decode: bytes, head_len: int) -> None:
    """Decode and print the response to the NC (LMK Check) command.

    Parameters
    ----------
    response_to_decode : bytes
        Raw response from the payShield.
    head_len : int
        Length of the message header.
    """
    response_str, msg_len, str_pointer = common_parser(response_to_decode, head_len)
    if response_str[str_pointer:str_pointer + 2] == '00':
        str_pointer += 2
        print("LMK CRC:", response_str[str_pointer:str_pointer + 16])
        str_pointer += 16
        print("Firmware number:", response_str[str_pointer:str_pointer + 9])


def decode_ja(response_to_decode: bytes, head_len: int) -> None:
    """Decode and print the response to the JA (Generate PIN) command.

    Parameters
    ----------
    response_to_decode : bytes
        Raw response from the payShield.
    head_len : int
        Length of the message header.
    """
    response_str, msg_len, str_pointer = common_parser(response_to_decode, head_len)
    if response_str[str_pointer:str_pointer + 2] == '00':
        str_pointer += 2
        print("Pin under the LMK:", response_str[str_pointer:str_pointer + 33])


def decode_j8(response_to_decode: bytes, head_len: int) -> None:
    """Decode and print the response to the J8 (Health Check Counts) command.

    Parameters
    ----------
    response_to_decode : bytes
        Raw response from the payShield.
    head_len : int
        Length of the message header.
    """
    response_str, msg_len, str_pointer = common_parser(response_to_decode, head_len)
    if response_str[str_pointer:str_pointer + 2] == '00':
        str_pointer += 2
        print("Serial Number: ", response_str[str_pointer:str_pointer + 12])
        str_pointer += 12
        print("Start Date: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("Start Time: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("End Date: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("End Time: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("Current Date: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("Current Time: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("Reboots: ", response_str[str_pointer:str_pointer + 10])
        str_pointer += 10
        print("Tampers: ", response_str[str_pointer:str_pointer + 10])
        str_pointer += 10
        print("Pin verifies/minute: ", response_str[str_pointer:str_pointer + 7])
        str_pointer += 7
        print("Pin verifies/hour: ", response_str[str_pointer:str_pointer + 5])
        str_pointer += 5
        print("Pin attacks: ", response_str[str_pointer:str_pointer + 8])


def decode_b2(response_to_decode: bytes, head_len: int) -> None:
    """Decode and print the response to the B2 (Echo) command.

    Parameters
    ----------
    response_to_decode : bytes
        Raw response from the payShield.
    head_len : int
        Length of the message header.
    """
    response_str, msg_len, str_pointer = common_parser(response_to_decode, head_len)
    if response_str[str_pointer:str_pointer + 2] == '00':
        str_pointer += 2
        print("Payload echoed: ", response_str[str_pointer:])


def decode_j2(response_to_decode: bytes, head_len: int) -> None:
    """Decode and print the response to the J2 (HSM Loading) command.

    Parameters
    ----------
    response_to_decode : bytes
        Raw response from the payShield.
    head_len : int
        Length of the message header.
    """
    response_str, msg_len, str_pointer = common_parser(response_to_decode, head_len)
    if response_str[str_pointer:str_pointer + 2] == '00':
        str_pointer += 2
        print("Serial Number: ", response_str[str_pointer:str_pointer + 12])
        str_pointer += 12
        print("Start Date: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("Start Time: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("End Date: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("End Time: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("Current Date: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("Current Time: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("Seconds: ", response_str[str_pointer:str_pointer + 10])
        str_pointer += 10
        while (str_pointer + 15) <= msg_len:
            print("Starting percentage: ", response_str[str_pointer:str_pointer + 3])
            str_pointer += 3
            print("Ending percentage: ", response_str[str_pointer:str_pointer + 3])
            str_pointer += 3
            print("Number Times Periods: ", response_str[str_pointer:str_pointer + 10])
            str_pointer += 10
            print("Delimiter: ", response_str[str_pointer:str_pointer + 1])
            str_pointer += 1
        print("")


def decode_j4(response_to_decode: bytes, head_len: int) -> None:
    """Decode and print the response to the J4 (Command Volumes) command.

    The message trailer is not considered.

    Parameters
    ----------
    response_to_decode : bytes
        Raw response from the payShield.
    head_len : int
        Length of the message header.
    """
    response_str, msg_len, str_pointer = common_parser(response_to_decode, head_len)
    if response_str[str_pointer:str_pointer + 2] == '00':
        str_pointer += 2
        print("Serial Number: ", response_str[str_pointer:str_pointer + 12])
        str_pointer += 12
        print("Start Date: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("Start Time: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("End Date: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("End Time: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("Current Date: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("Current Time: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("Seconds: ", response_str[str_pointer:str_pointer + 10])
        str_pointer += 10
        while (str_pointer + 12) <= msg_len:
            print("Command Code: ", response_str[str_pointer:str_pointer + 2])
            str_pointer += 2
            print("Transactions: ", response_str[str_pointer:str_pointer + 12])
            str_pointer += 12


def decode_jk(response_to_decode: bytes, head_len: int) -> None:
    """Decode and print the response to the JK (Instantaneous Health Check) command.

    The message trailer is not considered.

    Parameters
    ----------
    response_to_decode : bytes
        Raw response from the payShield.
    head_len : int
        Length of the message header.
    """
    CONSOLE_STATUS_CODE: dict[str, str] = {
        '0': 'unknown', '1': 'running', '2': 'not running', '3': 'console disabled by GUI',
    }
    TAMPER_STATUS_CODE: dict[str, str] = {
        '0': 'Unknown', '1': 'Not Tampered', '2': 'Tampered',
    }
    HOST_STATUS_CODE: dict[str, str] = {
        '0': 'unknown', '1': 'running', '2': 'not running', '3': 'not configured',
    }
    TAMPER_CAUSE_CODE: dict[str, str] = {
        '00': 'unknown', '01': 'temp out of range', '02': 'battery low',
        '03': 'erase button pressed', '04': 'security processor watchdog',
        '05': 'power too high', '06': 'security processor restart',
        '07': 'motion detected', '08': 'case tampered', '09': 'TSPP Module', '10': 'General',
    }
    LMK_ALGORITHM_CODE: dict[str, str] = {
        '0': '3DES2Key', '1': '3DES3Key', '2': 'AES 256-bit',
    }
    LMK_SCHEME_CODE: dict[str, str] = {'V': 'Variant', 'K': 'Keyblock'}
    LMK_STATUS_CODE: dict[str, str] = {'L': 'Live', 'T': 'Test'}
    LMK_AUTH_CODE: dict[str, str] = {'0': 'Not authorized', '1': 'Authorized'}
    FRAUD_CODE: dict[str, str] = {'0': 'not exceeded (or not enabled)', '1': 'exceeded'}

    response_str, msg_len, str_pointer = common_parser(response_to_decode, head_len)
    if response_str[str_pointer:str_pointer + 2] == '00':
        str_pointer += 2
        print("Serial Number: ", response_str[str_pointer:str_pointer + 12])
        str_pointer += 12
        print("System Date: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("System Time: ", response_str[str_pointer:str_pointer + 6])
        str_pointer += 6
        print("Console State: ", CONSOLE_STATUS_CODE.get(response_str[str_pointer:str_pointer + 1], '?'))
        str_pointer += 1
        print("payShield Manager State: ", CONSOLE_STATUS_CODE.get(response_str[str_pointer:str_pointer + 1], '?'))
        str_pointer += 1
        print("HOST 1 State: ", HOST_STATUS_CODE.get(response_str[str_pointer:str_pointer + 1], '?'))
        str_pointer += 1
        print("HOST 2 State: ", HOST_STATUS_CODE.get(response_str[str_pointer:str_pointer + 1], '?'))
        str_pointer += 1
        print("Reserved: ", response_str[str_pointer:str_pointer + 1])
        str_pointer += 1
        print("Reserved: ", response_str[str_pointer:str_pointer + 1])
        str_pointer += 1
        tamper_state = response_str[str_pointer:str_pointer + 1]
        print("Tamper State: ", TAMPER_STATUS_CODE.get(tamper_state, '?'))
        str_pointer += 1
        if tamper_state == '2':
            print("Tamper Cause: ", TAMPER_CAUSE_CODE.get(response_str[str_pointer:str_pointer + 2], '?'))
            str_pointer += 2
            print("Tamper Date: ", response_str[str_pointer:str_pointer + 6])
            str_pointer += 6
            print("Tamper Time: ", response_str[str_pointer:str_pointer + 6])
            str_pointer += 6
        lmk_loaded = response_str[str_pointer:str_pointer + 2]
        print("Number of LMK Loaded: ", lmk_loaded)
        str_pointer += 2
        print("Number of Test LMK: ", response_str[str_pointer:str_pointer + 2])
        str_pointer += 2
        print("Number of Old LMK: ", response_str[str_pointer:str_pointer + 2])
        str_pointer += 2
        print("There are ", lmk_loaded, " LMK(s) loaded")
        try:
            lmks_loaded_num = int(lmk_loaded)
        except ValueError:
            lmks_loaded_num = -1
        if lmks_loaded_num > 0:
            remaining = response_str[str_pointer:]
            lmks_string = str.split(remaining, '\x15')[0]
            lmks_array = str.split(lmks_string, '\x14')
            for lmk in lmks_array:
                if len(lmk) > 0:
                    p = 0
                    print("LMK ID: ", lmk[p:p + 2])
                    p += 2
                    print("Authorised: ", LMK_AUTH_CODE.get(lmk[p:p + 1], '?'))
                    p += 1
                    print("Num Authorised Activities: ", lmk[p:p + 2])
                    p += 2
                    print("LMK Scheme: ", LMK_SCHEME_CODE.get(lmk[p:p + 1], '?'))
                    p += 1
                    print("Algorithm: ", LMK_ALGORITHM_CODE.get(lmk[p:p + 1], '?'))
                    p += 1
                    print("Status: ", LMK_STATUS_CODE.get(lmk[p:p + 1], '?'))
                    p += 1
                    print("Comments: ", lmk[p:])
                    print("")
        fraud_detection = str.split(response_str[str_pointer:], '\x15')[1]
        print("Fraud detection Exceeded: ", FRAUD_CODE.get(fraud_detection[0], '?'))
        print("PIN attacks exceeded: ", FRAUD_CODE.get(fraud_detection[1], '?'))
        print("")


def decode_ecc(response_to_decode: bytes, head_len: int) -> None:
    """Decode and print the response to the FY (ECC Key Generation) command.

    Parameters
    ----------
    response_to_decode : bytes
        Raw response from the payShield.
    head_len : int
        Length of the message header.
    """
    response_str, msg_len, str_pointer = common_parser(response_to_decode, head_len)
    if response_str[str_pointer:str_pointer + 2] == '00':
        str_pointer += 2
        key_len = int(response_str[str_pointer:str_pointer + 4])
        print("ECC Public Key Length: ", key_len)
        str_pointer += 4
        print("ECC Public Key", bytes.hex(response_to_decode[str_pointer:str_pointer + key_len]))
        print(
            "Public/private separator: ",
            response_to_decode[str_pointer + key_len:str_pointer + key_len + 1].decode('ascii', 'ignore'),
        )
        str_pointer += key_len + 1
        print("ECC Private Key under LMK", bytes.hex(response_to_decode[str_pointer:]))


# ---------------------------------------------------------------------------
# Decoder dispatch table
# ---------------------------------------------------------------------------

#: Maps the two-character command verb to the matching decoder function.
#: A missing key means no decoder is available for that command.
DECODERS: Dict[str, object] = {
    'NO': decode_no,
    'NC': decode_nc,
    'N0': decode_n0,
    'J8': decode_j8,
    'J2': decode_j2,
    'J4': decode_j4,
    'JK': decode_jk,
    'B2': decode_b2,
    'FY': decode_ecc,
    'NI': decode_ni,
    'JA': decode_ja,
}
