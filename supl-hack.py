#!/usr/bin/python3

from binascii import a2b_hex
import logging
from random import randint
import socket
import ssl
import struct
import threading


SUPL_HOST = "supl.google.com"
SUPL_PORT = 7275
MY_IMSI = "262011234567890"


logging.basicConfig(level=logging.INFO)
log = logging.getLogger


class closed(socket.error):
    pass


def to_tbcd(imsi: str) -> bytes:
    imsi += "F" * (len(imsi) % 2)
    reversed = imsi[::-1]
    twisted = ""
    while reversed:
        twisted = reversed[:2] + twisted
        reversed = reversed[2:]
    return a2b_hex(twisted)


def to_bitstring(data: bytes) -> str:
    rv = ""
    for i in data:
        rv += "%08d" % int(bin(i)[2:])
    return rv


def from_bitstring(data: str) -> bytes:
    ld = len(data)
    ba = bytearray(ld // 8)
    for i in range(0, len(data), 8):
        ba[i // 8] = int(data[i:i+8], 2)
    return bytes(ba)


def forward_packet(fd, srv, orig, replacement):
    data = fd.recv(2)
    if not data:
        raise closed()
    length = struct.unpack(">H", data)[0]
    data += fd.recv(length - 2)
    bs = to_bitstring(data)
    if orig in bs:
        log(__name__).info("Imsi replaced")
    bs = bs.replace(orig, replacement)
    data = from_bitstring(bs)
    srv.send(data)


def handle_connection(fd, peer):
    log(__name__).info("Connection from %s:%d accepted", *peer)
    my_imsi = to_bitstring(to_tbcd(MY_IMSI))
    fake = to_bitstring(to_tbcd("26201%10d" % randint(1011111111, 9999999999)))
    try:
        fd.settimeout(1.0)
        raw_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv = ssl.wrap_socket(raw_srv)
        srv.connect((SUPL_HOST, SUPL_PORT))

        while True:
            forward_packet(fd, srv, my_imsi, fake)
            forward_packet(srv, fd, fake, my_imsi)
    except socket.timeout:
        pass
    except closed:
        pass
    finally:
        fd.close()
        srv.close()
    log(__name__).info("Connection to %s:%d closed", *peer)


def main(port):
    a_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    a_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#  uncomment this for TLS support
#    a_sock = ssl.wrap_socket(a_sock,
#                             "KEYFILE.pem",
#                             "CERTFILE.pem",
#                             server_side=True)
    a_sock.bind(("0.0.0.0", port))
    a_sock.listen(5)
    log(__name__).info("Listening on port %d", port)
    while True:
        fd, peer = a_sock.accept()
        t = threading.Thread(target=handle_connection, args=(fd, peer),
                             daemon=True)
        t.start()


main(7275)
