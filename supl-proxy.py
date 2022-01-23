#!/usr/bin/python3

from binascii import a2b_hex
from copy import deepcopy
import glob
import json
import logging
from random import randint
import socket
import ssl
import struct
import threading

import asn1tools


SUPL_HOST = "supl.google.com"
SUPL_PORT = 7275

logging.basicConfig(level=logging.INFO)
log = logging.getLogger


class closed(socket.error):
    pass


def dump(pdu):

    class BytesSerializer(json.JSONEncoder):
        def default(self, o):
            if isinstance(o, bytes):
                return o.hex(" ")
            return json.JSONEncoder.default(self, o)

    print(json.dumps(pdu, indent=2, cls=BytesSerializer))


def to_tbcd(imsi: str) -> bytes:
    imsi += "F" * (len(imsi) % 2)
    reversed = imsi[::-1]
    twisted = ""
    while reversed:
        twisted = reversed[:2] + twisted
        reversed = reversed[2:]
    return a2b_hex(twisted)


def from_tbcd(enc_imsi: bytes) -> str:
    imsi = ""
    for b in enc_imsi:
        imsi += ("%02x" % b)[::-1]
    return imsi.upper().rstrip("F")


def test_path(pdu, keys, value=None):
    try:
        for k in keys:
            pdu = pdu[k]
        if value is not None:
            assert(pdu == value)
        return True
    except Exception:
        return False


def forward_packet(supl_db, rrlp_db, fd, srv, replacement):
    orig_imsi = None
    data = fd.recv(2)
    if not data:
        raise closed()
    length = struct.unpack(">H", data)[0]
    data += fd.recv(length - 2)
    pdu = supl_db.decode("ULP-PDU", data)

    if test_path(pdu, ["sessionID", "setSessionID", "setId", 0], "imsi"):
        orig_imsi = from_tbcd(pdu["sessionID"]["setSessionID"]["setId"][1])
        if replacement:
            pdu["sessionID"]["setSessionID"]["setId"] = ('imsi', to_tbcd(replacement))
    pretty_pdu = deepcopy(pdu)
    if test_path(pdu, ["message", 0], "msSUPLPOS") and \
       test_path(pdu, ["message", 1, "posPayLoad", 0], "rrlpPayload"):
        rrlp = pdu["message"][1]["posPayLoad"][1]
        pretty_pdu["message"][1]["posPayLoad"] = ("rrlpPayload", rrlp_db.decode("PDU", rrlp))
    dump(pretty_pdu)
    data = supl_db.encode("ULP-PDU", pdu)
    srv.send(data)
    return orig_imsi


def handle_connection(supl_db, rrlp_db, fd, peer):
    log(__name__).info("Connection from %s:%d accepted", *peer)

    fake = "26201%10d" % randint(1011111111, 9999999999)
    try:
        fd.settimeout(1.0)
        raw_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv = ssl.wrap_socket(raw_srv)
        srv.connect((SUPL_HOST, SUPL_PORT))

        while True:
            orig_imsi = forward_packet(supl_db, rrlp_db, fd, srv, fake)
            if orig_imsi:
                log(__name__).info("Replacing imsi %s", orig_imsi)
            forward_packet(supl_db, rrlp_db, srv, fd, orig_imsi)
    except socket.timeout:
        pass
    except closed:
        pass
    finally:
        fd.close()
        srv.close()
    log(__name__).info("Connection to %s:%d closed", *peer)


def main(port):
    ulp_files = glob.glob("asn1/supl-*.asn")
    rrlp_files = glob.glob("asn1/rrlp-*.asn")
    supl_db = asn1tools.compile_files(ulp_files, "uper", cache_dir="cache")
    rrlp_db = asn1tools.compile_files(rrlp_files, "uper", cache_dir="cache")

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
        t = threading.Thread(target=handle_connection, args=(supl_db, rrlp_db, fd, peer),
                             daemon=True)
        t.start()


main(7275)
