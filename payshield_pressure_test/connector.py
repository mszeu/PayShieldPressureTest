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
connector.py
------------
Low-level network connector for the payShield host port.
Supports TCP, UDP, and TLS transports.
"""

import logging
import socket
import ssl
from struct import pack

logger = logging.getLogger(__name__)


class PayConnector:
    """Represents the connection with the payShield host port.

    Supports tcp, udp, and tls transports.

    Attributes
    ----------
    ssl_sock : ssl.SSLSocket
        The SSLSocket in case of a tls connection.
    connection : socket.socket
        The underlying socket. Should not be accessed directly.
    host : str
        The host IP address or hostname.
    port : int
        The TCP/UDP port to connect to.
    protocol : str
        Transport protocol: ``'tcp'``, ``'tls'``, or ``'udp'``.
    connected : bool
        ``True`` when an open connection already exists and can be reused.
    keyfile : str | None
        Full path to the client key file (TLS only).
    crtfile : str | None
        Full path to the client certificate file (TLS only).
    context : ssl.SSLContext | None
        The SSLContext object (TLS only).
    """

    def __init__(
            self,
            host: str,
            port: int,
            protocol: str,
            keyfile: str | None = None,
            crtfile: str | None = None,
    ):
        """Initialise a PayConnector instance.

        Parameters
        ----------
        host : str
            The host IP address or hostname.
        port : int
            The TCP/UDP port to connect to.
        protocol : str
            Transport protocol: ``'tcp'``, ``'tls'``, or ``'udp'``.
        keyfile : str, optional
            Full path to the client key file (required when *protocol* is
            ``'tls'``).
        crtfile : str, optional
            Full path to the client certificate file (required when *protocol*
            is ``'tls'``).

        Raises
        ------
        ValueError
            If *protocol* is not ``'tcp'``, ``'tls'``, or ``'udp'``.
        ValueError
            If *protocol* is ``'tls'`` but *keyfile* or *crtfile* is omitted.
        """
        self.keyfile = keyfile
        self.crtfile = crtfile
        self.ssl_sock = None
        self.connection = None
        self.context = None
        self.host = host
        self.port = port
        self.protocol = protocol
        self.connected = False

        if protocol not in ('udp', 'tcp', 'tls'):
            raise ValueError("protocol must be udp, tcp or tls")
        if protocol == 'tls' and (keyfile is None or crtfile is None):
            raise ValueError("keyfile and crtfile parameters are both required")

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def send_command(self, host_command: str) -> bytes | None:
        """Send *host_command* to the payShield and return the raw response.

        Establishes the connection the first time it is called; subsequent
        calls reuse the open socket.

        Parameters
        ----------
        host_command : str
            The host command string to send (without the two-byte length
            prefix — that is prepended automatically).

        Returns
        -------
        bytes | None
            The raw response bytes (including the two-byte length prefix),
            or ``None`` on error.
        """
        size = pack('>h', len(host_command))
        message = size + host_command.encode()

        try:
            if self.protocol == 'tcp':
                if not self.connected:
                    self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.connection.connect((self.host, self.port))
                    self.connected = True
                self.connection.send(message)
                raw_len = self._recv_exact(self.connection, 2)
                expected_len = int.from_bytes(raw_len, byteorder='big')
                data: bytes = raw_len + self._recv_exact(self.connection, expected_len)
                return data

            elif self.protocol == 'tls':
                if not self.connected:
                    self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    self.context.load_cert_chain(certfile=self.crtfile, keyfile=self.keyfile)
                    self.context.check_hostname = False
                    self.context.verify_mode = ssl.CERT_NONE
                    self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.ssl_sock = self.context.wrap_socket(self.connection, server_side=False)
                    self.ssl_sock.connect((self.host, self.port))
                    self.connected = True
                self.ssl_sock.send(message)
                raw_len = self._recv_exact(self.ssl_sock, 2)
                expected_len = int.from_bytes(raw_len, byteorder='big')
                data = raw_len + self._recv_exact(self.ssl_sock, expected_len)
                return data

            elif self.protocol == 'udp':
                if not self.connected:
                    self.connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self.connection.settimeout(5)
                    self.connected = True
                self.connection.sendto(message, (self.host, self.port))
                data_tuple = self.connection.recvfrom(65507)
                return data_tuple[0]

        except (ConnectionError, TimeoutError) as e:
            print("Connection issue: ", e)
            logger.exception("Socket Connection issue: " + str(e))
            self._force_close()

        except FileNotFoundError as e:
            print(
                "The client certificate file or the client key file cannot be "
                "found or accessed.\n"
                "Check value passed to the parameters --keyfile and --crtfile",
                e,
            )
            self._force_close()

        except ssl.SSLError as e:
            self._force_close()
            raise ssl.SSLError("TLS connection error: ", e)

        except Exception as e:
            print("Unexpected issue: ", e)
            logger.exception("Unexpected socket issue")
            self._force_close()

        return None

    def close(self) -> None:
        """Close the active connection, if any."""
        if self.connected:
            if self.ssl_sock:
                self.ssl_sock.close()
            self.connection.close()
            self.connected = False

    # ------------------------------------------------------------------
    # Context-manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> "PayConnector":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Close the connection when leaving a ``with`` block.

        Returns ``False`` so that any exception is propagated normally.
        """
        self.close()
        return False

    def __del__(self) -> None:
        """Fallback cleanup when the instance is garbage-collected.

        For guaranteed cleanup, prefer using ``PayConnector`` as a context
        manager (``with`` statement).
        """
        if hasattr(self, 'connection') and self.connection:
            self.close()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _force_close(self) -> None:
        """Force-close all sockets and reset connection state.

        Called internally after errors to prevent file-descriptor leaks.
        """
        self.connected = False
        if self.ssl_sock:
            try:
                self.ssl_sock.close()
            except Exception:
                pass
            self.ssl_sock = None
        if self.connection:
            try:
                self.connection.close()
            except Exception:
                pass
            self.connection = None

    def _recv_exact(self, sock, num_bytes: int) -> bytes:
        """Read exactly *num_bytes* bytes from *sock*, handling partial reads.

        Parameters
        ----------
        sock : socket.socket | ssl.SSLSocket
            The socket to read from.
        num_bytes : int
            The exact number of bytes to receive.

        Returns
        -------
        bytes
            The received data.

        Raises
        ------
        ConnectionError
            If the connection closes before all bytes arrive.
        """
        data = b''
        while len(data) < num_bytes:
            chunk = sock.recv(num_bytes - len(data))
            if not chunk:
                raise ConnectionError("Connection closed before all data was received")
            data += chunk
        return data
