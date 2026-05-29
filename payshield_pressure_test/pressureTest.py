#!/usr/bin/env python3
# payShield test utility by Marco S. Zuppone - msz@msz.eu
# Project name: payShieldPressureTest
# Python script name: pressureTest.py
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
# Please refer to the LICENSE file for more information about licensing
# and to the README.md file for more information about the usage of it.

"""
pressureTest.py
-------
Entry point for payShieldPressureTest.

Parses command-line arguments, builds the payShield host command, then drives
the test loop (finite or infinite) using the PayConnector and run_test
helpers from the other modules.
"""

import argparse
import logging
import sys
import threading
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

from payshield_pressure_test.connector import PayConnector
from payshield_pressure_test.decoders import DECODERS
from payshield_pressure_test.runner import run_test
from payshield_pressure_test.updater import UpdateChecker

VERSION = "1.5.4.3"


def main() -> None:
    # ------------------------------------------------------------------ #
    # Bootstrap: update checker + logging                                 #
    # ------------------------------------------------------------------ #
    update_checker_instance = UpdateChecker(VERSION)

    LOG_DIR = Path(update_checker_instance.get_config_file_full(""))
    LOG_DIR.mkdir(exist_ok=True)

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            RotatingFileHandler(
                LOG_DIR / "pressureTest.log",
                maxBytes=2 * 1024 * 1024,  # 2 MB
                backupCount=5,
                encoding="utf-8",
            )
        ],
    )

    print("PayShield stress utility, version " + VERSION + ", by Marco S. Zuppone - msz@msz.eu - https://msz.eu")
    print("To get more info about the usage invoke it with the -h option")
    print("This software is open source and it is under the Affero AGPL 3.0 license")
    print("GitHub repository: https://github.com/mszeu/PayShieldPressureTest")

    if update_checker_instance.update_available():
        print("A new version of the software is available.")
        print("Please update from https://github.com/mszeu/PayShieldPressureTest")
    print("")

    # ------------------------------------------------------------------ #
    # CLI argument parsing                                                #
    # ------------------------------------------------------------------ #
    parser = argparse.ArgumentParser(
        description="Generates workload on PayShield 10k and 9k for the sake of testing and demonstration.",
        epilog=(
            "For any questions, feedback, suggestions or sending money (yes...it's a dream, I know), "
            "you can contact the author at msz@msz.eu"
        ),
    )
    parser.add_argument("host", help="Ip address or hostname of the payShield")
    parser.add_argument(
        "--port", "-p",
        help="The host port. If not specified the default port is 1500.",
        default=1500, type=int,
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--key", help="RSA key length. Accepted values are between 320 and 4096.", type=int)
    group.add_argument("--nc", help="Perform a NC test.", action="store_true")
    group.add_argument("--no", help="Retrieve HSM status information using NO command.", action="store_true")
    group.add_argument("--ni", help="Return information about the Ethernet Host port 1.", action="store_true")
    group.add_argument("--pci", help="Check if the HSM is set in PCI compliant mode.", action="store_true")
    group.add_argument("--j2", help="Get HSM Loading using J2 command.", action="store_true")
    group.add_argument("--j4", help="Get Host Command Volumes using J4 command.", action="store_true")
    group.add_argument("--j8", help="Get Health Check Accumulated Counts using J8 command.", action="store_true")
    group.add_argument("--jk", help="Get Instantaneous Health Check Status using JK command.", action="store_true")
    group.add_argument("--b2", help="Echo received data back to the user.", action="store_true")
    group.add_argument("--pingen", help="Generate a random pin of 5 digits protected under the LMK.",
                       action="store_true")
    group.add_argument("--randgen", help="Generate a random value 8 bytes long.", action="store_true")
    group.add_argument(
        "--ecc",
        help="Generate an ECC public/private key pair using the Elliptic Curve algorithm curve NIST P-521.",
        action="store_true",
    )

    parser.add_argument("--ecc-curve", help="Select the ECC curve.", default='0', type=str, choices=['0', '1', '2'])
    parser.add_argument("--key-use", help="Select the key mode of use.", default='S', type=str.upper,
                        choices=['S', 'X', 'N'])
    parser.add_argument("--key-exportability", help="Select the key exportability.", default='S', type=str.upper,
                        choices=['N', 'E', 'S'])
    parser.add_argument(
        "--header",
        help="Header string to prepend to the host command. If not specified the default is HEAD.",
        default="HEAD", type=str,
    )
    parser.add_argument("--forever", help="If this option is specified the program runs forever.", action="store_true")
    parser.add_argument(
        "--decode",
        help="If specified the reply of the payShield is interpreted if a decoder function for that command has been implemented.",
        action="store_true",
    )
    parser.add_argument(
        "--times",
        help="How many times to repeat the operation. If not specified the default is 1000.",
        type=int, default=1000,
    )
    parser.add_argument("--proto", help="Accepted values are tcp, udp or tls. The default is tcp", default="tcp",
                        choices=["tcp", "udp", "tls"], type=str.lower)
    parser.add_argument("--keyfile", help="Client key file, used if the protocol is TLS.", type=Path,
                        default="client.key")
    parser.add_argument("--crtfile", help="Client certificate file, used if the protocol is TLS.", type=Path,
                        default="client.crt")
    parser.add_argument("--echo", help="Payload sent using the echo command B2.", type=str,
                        default="PayShieldStress Echo Test", action="store")
    parser.add_argument("--timing", help="Measure the time consumed by the operations", action="store_true")
    parser.add_argument("--no-upd-check", help="Avoid checking on GitHub if a new version is available",
                        action="store_true")

    args = parser.parse_args()

    # ------------------------------------------------------------------ #
    # Start update checker thread                                         #
    # ------------------------------------------------------------------ #
    updater_thread = threading.Thread(target=update_checker_instance.check_for_updates, daemon=True)
    if update_checker_instance.should_check_for_updates() and not args.no_upd_check:
        updater_thread.start()

    # ------------------------------------------------------------------ #
    # Argument validation                                                 #
    # ------------------------------------------------------------------ #
    if args.times <= 0:
        parser.error("--times must be a positive integer (greater than 0).")
    if len(args.header) > 255:
        parser.error("--header must be a string not longer than 255 characters.")
    if args.port < 0 or args.port > 65535:
        parser.error("--port must be a positive integer between 0 and 65535.")

    # ------------------------------------------------------------------ #
    # Build the host command string                                       #
    # ------------------------------------------------------------------ #
    # The order of the IF/ELIF block matters because of the default arguments.
    # All mutually exclusive options must be handled here with ELIF.
    command = ''

    if args.key is not None:
        if 320 <= args.key <= 4096:
            k_len_str = str(args.key)
            if len(k_len_str) <= 3:
                k_len_str = '0' + k_len_str
            command = args.header + 'EI2' + k_len_str + '01#0000'
        else:
            print("The key length value needs to be between 320 and 4096")
            sys.exit()
    elif args.nc:
        command = args.header + 'NC'
    elif args.no:
        command = args.header + 'NO00'
    elif args.ni:
        command = args.header + 'NI11'
    elif args.pci:
        command = args.header + 'NO01'
    elif args.j2:
        command = args.header + 'J2'
    elif args.j4:
        command = args.header + 'J4'
    elif args.j8:
        command = args.header + 'J8'
    elif args.jk:
        command = args.header + 'JK'
    elif args.randgen:
        command = args.header + 'N0008'
    elif args.ecc:
        command = args.header + 'FY010' + args.ecc_curve + '03#' + args.key_use + '00' + args.key_exportability + '00'
    elif args.pingen:
        command = args.header + 'JA1234567890128;05'

    # B2 (echo) is not in the mutually-exclusive group so it is handled separately
    if args.b2:
        h_padding = '0000'
        len_echo_message = len(args.echo)
        hex_string_len = hex(len_echo_message).lstrip('0x').upper()
        hex_string_len = h_padding[:4 - len(hex_string_len)] + hex_string_len
        command = args.header + 'B2' + hex_string_len + args.echo

    # Guard: a command must have been set by now
    if len(command) == 0:
        print("You forgot to specify the action you want to perform on the payShield")
        sys.exit()

    # ------------------------------------------------------------------ #
    # TLS-specific pre-flight checks                                      #
    # ------------------------------------------------------------------ #
    if args.proto == 'tls':
        if not (args.keyfile.exists() and args.crtfile.exists()):
            print(
                "The client certificate file or the client key file cannot be found or accessed.\n"
                "Check value passed to the parameters --keyfile and --crtfile"
            )
            print("You passed these values:")
            print("Certificate file:", args.crtfile)
            print("Key file:", args.keyfile)
            sys.exit()
        if args.port < 2500:
            print(
                "WARNING: generally the TLS base port is 2500. You are instead using the port ",
                args.port,
                " please check that you passed the right value to the --port parameter",
            )

    # ------------------------------------------------------------------ #
    # Main test loop                                                      #
    # ------------------------------------------------------------------ #
    with PayConnector(args.host, args.port, args.proto, args.keyfile, args.crtfile) as payConnInst:
        if args.forever:
            i = 1
            while True:
                print("Iteration: ", i)
                decoder = DECODERS.get(command[len(args.header):len(args.header) + 2], None) if args.decode else None
                run_test(payConnInst, command, len(args.header), decoder)
                i += 1
                print("")
        else:
            t1 = time.perf_counter(), time.process_time()
            for i in range(args.times):
                print("Iteration: ", i + 1, " of ", args.times)
                decoder = DECODERS.get(command[len(args.header):len(args.header) + 2], None) if args.decode else None
                run_test(payConnInst, command, len(args.header), decoder)
                print("")
            t2 = time.perf_counter(), time.process_time()
            if args.timing:
                print(f"Operations performed: {args.times}")
                print(f" Real time: {t2[0] - t1[0]:.2f} seconds")
                print(f" CPU time:  {t2[1] - t1[1]:.2f} seconds")
            print("DONE")

    if updater_thread.is_alive():
        updater_thread.join(6)


if __name__ == "__main__":
    main()
