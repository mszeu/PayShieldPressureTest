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
error_codes.py
--------------
Maps payShield 10K numeric/alphanumeric result codes to their human-readable
descriptions, as documented in:
  payShield 10K Core Host Commands v1 – Rev. A – 04 August 2020 (PUGD0537-004)
"""

PAYSHIELD_ERROR_CODE: dict[str, str] = {
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
    '80': 'Data length error. The amount of MAC data (or other data) is greater than or less than the expected amount.',
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
    'BE': 'Invalid key block header ID',
    'D2': 'Invalid curve reference',
    'D3': 'Invalid Key Encoding',
    'E0': 'Invalid command version number',
}


def payshield_error_codes(error_code: str) -> str:
    """Return the human-readable description for a payShield result code.

    Parameters
    ----------
    error_code : str
        The two-character status code returned by the payShield 10K.

    Returns
    -------
    str
        The matching error description, or ``"Unknown error"`` when the code
        is not present in the table.
    """
    return PAYSHIELD_ERROR_CODE.get(error_code, "Unknown error")
