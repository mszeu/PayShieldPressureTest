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
runner.py
---------
Orchestrates the send/receive cycle for a single payShield command and
provides helpers for validating the raw response.
"""

import string
from struct import pack
from types import FunctionType
from typing import Tuple

from .connector import PayConnector
from .error_codes import payshield_error_codes


# ---------------------------------------------------------------------------
# Response validation helpers
# ---------------------------------------------------------------------------

def test_printable(input_str: str) -> bool:
    """Return ``True`` if every character in *input_str* is printable ASCII.

    Parameters
    ----------
    input_str : str
        The string to test.

    Returns
    -------
    bool
    """
    return all(c in string.printable for c in input_str)


def check_returned_command_verb(
        result_returned: bytes,
        head_len: int,
        command_sent: str,
) -> Tuple[int, str, str]:
    """Check that the command verb in the response matches the request.

    The payShield convention is that the response verb is the request verb
    with the second character incremented by one (e.g. ``'NC'`` → ``'ND'``).

    Parameters
    ----------
    result_returned : bytes
        Raw bytes returned by the payShield.
    head_len : int
        Length of the message header.
    command_sent : str
        The full command string that was sent (header + verb + payload).

    Returns
    -------
    status : int
        ``0`` if the response verb is consistent with the request, ``-1``
        otherwise.
    verb_sent : str
        The two-character verb that was sent.
    verb_returned : str
        The two-character verb present in the response.
    """
    verb_returned = result_returned[2 + head_len:][:2]
    verb_sent = command_sent[head_len:][:2]
    verb_expected = verb_sent[0:1] + chr(ord(verb_sent[1:2]) + 1)
    if verb_returned != verb_expected.encode():
        return -1, verb_sent, verb_returned.decode()
    return 0, verb_sent, verb_returned.decode()


def check_return_message(result_returned: bytes, head_len: int) -> Tuple[str, str]:
    """Validate the response length and extract the payShield result code.

    Parameters
    ----------
    result_returned : bytes
        Raw bytes returned by the payShield.
    head_len : int
        Length of the message header.

    Returns
    -------
    ret_code : str
        The two-character result code (e.g. ``'00'`` for success), or
        ``'ZZ'`` when the message is malformed or cannot be parsed.
    description : str
        Human-readable description of the result code.
    """
    if len(result_returned) < 2 + head_len + 2:
        return "ZZ", "Incomplete message"
    try:
        expected_msg_len = int.from_bytes(result_returned[:2], byteorder='big', signed=False)
    except ValueError:
        return "ZZ", "Malformed message"
    except Exception:
        return "ZZ", "Unknown message length parsing error"

    if len(result_returned) - 2 != expected_msg_len:
        return "ZZ", "Length mismatch"

    ret_code_position = 2 + head_len + 2
    try:
        ret_code = result_returned[ret_code_position:ret_code_position + 2].decode()
    except (ValueError, UnicodeDecodeError):
        return "ZZ", "message result code parsing error"
    except Exception:
        return "ZZ", "Unknown message result code parsing error"

    return ret_code, payshield_error_codes(ret_code)


# ---------------------------------------------------------------------------
# Main test runner
# ---------------------------------------------------------------------------

def run_test(
        payConnectorInstance: PayConnector,
        host_command: str,
        header_len: int = 4,
        decoder_funct: FunctionType = None,
) -> str:
    """Send *host_command* to the payShield, print the result, and return the
    result code.

    Reuses the open connection held by *payConnectorInstance* (or establishes
    one if needed). Optionally calls *decoder_funct* to pretty-print the
    response payload.

    Parameters
    ----------
    payConnectorInstance : PayConnector
        An initialised (and preferably open) ``PayConnector`` instance.
    host_command : str
        The full command string to send (header + verb + payload).
    header_len : int, optional
        Length of the message header.  Defaults to ``4`` (factory default for
        payShield 10K).
    decoder_funct : FunctionType, optional
        A callable that accepts ``(response_bytes, header_len)`` and prints
        the decoded response fields.  Pass ``None`` to skip decoding.

    Returns
    -------
    str
        The two-character result code from the payShield, or ``'Error'`` /
        ``'ZZ'`` when something went wrong.
    """
    return_code_tuple = ['ZZ', 'Error']
    try:
        size = pack('>h', len(host_command))
        message = size + host_command.encode()

        data = payConnectorInstance.send_command(host_command)
        if data is None:
            return 'Error'

        check_result_tuple = (-1, "", "")
        return_code_tuple = check_return_message(data, header_len)
        if return_code_tuple[0] != "ZZ":
            print()
            check_result_tuple = check_returned_command_verb(data, header_len, host_command)

        print("Return code: " + str(return_code_tuple[0]) + " " + return_code_tuple[1])
        if check_result_tuple[0] != 0:
            print("NOTE: The response received from the HSM seems unrelated to the request!")

        print("Command sent/received: " + check_result_tuple[1] + " ==> " + check_result_tuple[2])

        if test_printable(message[2:].decode("ascii", "ignore")):
            print("sent data (ASCII) :", message[2:].decode("ascii", "ignore"))
        print("sent data (HEX) :", bytes.hex(message))

        if test_printable((data[2:]).decode("ascii", "ignore")):
            print("received data (ASCII):", data[2:].decode("ascii", "ignore"))
        print("received data (HEX) :", bytes.hex(data))

        if (decoder_funct is not None) and callable(decoder_funct):
            print("")
            print("-----DECODING RESPONSE-----")
            decoder_funct(data, header_len)

    except ConnectionError as e:
        print("Connection issue: ", e)
    except FileNotFoundError as e:
        print(
            "The client certificate file or the client key file cannot be found or accessed.\n"
            "Check value passed to the parameters --keyfile and --crtfile",
            e,
        )
    except Exception as e:
        print("Unexpected issue:", e)
    finally:
        return return_code_tuple[0]
