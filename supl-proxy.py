#!/usr/bin/python3
# -*- coding: utf-8 -*-

import argparse
from binascii import a2b_hex
from copy import deepcopy
from datetime import datetime
import glob
import json
import logging
import os
from random import randint
import socket
import ssl
import struct
import threading

import asn1tools

log = logging.getLogger


class closed(socket.error):
    pass


def dump(direction, pdu):

    class BytesSerializer(json.JSONEncoder):
        def default(self, o):
            if isinstance(o, bytes):
                return o.hex(" ")
            if isinstance(o, datetime):
                return o.strftime("%F_%T")
            return json.JSONEncoder.default(self, o)

    log(__name__).info("Packet from %s\n%s",
                       direction,
                       json.dumps(pdu, indent=2, cls=BytesSerializer))


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


def forward_packet(supl_db, rrlp_db, direction, fd, srv, replacement):
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
    if test_path(pdu, ["message", 1, "position", "positionEstimate"]):
        pos = pdu["message"][1]["position"]["positionEstimate"]
        pretty_pos = pretty_pdu["message"][1]["position"]["positionEstimate"]
        pretty_pos["latitude"] = pos["latitude"] * 90.0 / (2 << 22)
        pretty_pos["longitude"] = pos["longitude"] * 360.0 / (2 << 23)

    dump(direction, pretty_pdu)
    data = supl_db.encode("ULP-PDU", pdu)
    srv.send(data)
    return orig_imsi


def handle_connection(args, supl_db, rrlp_db, fd, peer):
    log(__name__).info("Connection from %s:%d accepted", *peer)
    host, port = args.server.rsplit(":", 2)

    fake = "26201%10d" % randint(1011111111, 9999999999)
    try:
        fd.settimeout(1.0)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if args.tls:
            srv = ssl.wrap_socket(srv)
        srv.connect((host, int(port)))

        while True:
            orig_imsi = forward_packet(supl_db, rrlp_db, "mobile", fd, srv, fake)
            if orig_imsi:
                log(__name__).info("Replacing imsi %s", orig_imsi)
            forward_packet(supl_db, rrlp_db, "server", srv, fd, orig_imsi)
    except socket.timeout:
        pass
    except closed:
        pass
    finally:
        fd.close()
        srv.close()
    log(__name__).info("Connection to %s:%d closed", *peer)


def main(args):
    ulp_files = glob.glob(os.path.join(args.grammar, "supl-*.asn"))
    rrlp_files = glob.glob(os.path.join(args.grammar, "rrlp-*.asn"))
    supl_db = asn1tools.compile_files(ulp_files, "uper", cache_dir="cache")
    rrlp_db = asn1tools.compile_files(rrlp_files, "uper", cache_dir="cache")

    a_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    a_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if args.key and args.cert:
        a_sock = ssl.wrap_socket(a_sock, keyfile=args.key, certfile=args.cert,
                                 server_side=True)
    a_sock.bind(("0.0.0.0", args.port))
    a_sock.listen(5)
    log(__name__).info("Listening on port %d", args.port)
    while True:
        fd, peer = a_sock.accept()
        t = threading.Thread(target=handle_connection, args=(args, supl_db, rrlp_db, fd, peer),
                             daemon=True)
        t.start()


parser = argparse.ArgumentParser(description='Supl Proxy')
parser.add_argument('-s', '--server', help="SUPL server (host:port)",
                    default="supl.google.com:7275")
parser.add_argument('-t', '--tls', action="store_true", help="SUPL server uses TLS", default=False)
parser.add_argument('-c', '--cert', help="proxy TLS certificate", default=None)
parser.add_argument('-k', '--key', help="proxy TLS keyfile", default=None)
parser.add_argument('-p', '--port', type=int, help="proxy port", default=7275)
parser.add_argument('-g', '--grammar', help="path to asn.1 grammar", default="asn1")
parser.add_argument('-l', '--logfile', help="path to logfile", default="/tmp/supl-proxy.log")
args = parser.parse_args()

logging.basicConfig(filename=args.logfile,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                    level=logging.INFO)


main(args)
