#!/usr/lib/supl-proxy/venv/bin/python3
# -*- coding: utf-8 -*-

import argparse
import asyncio
from binascii import a2b_hex
from copy import deepcopy
from datetime import datetime
from functools import partial
import glob
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from python_socks.async_.asyncio import Proxy
from random import randint
import ssl
import struct
from typing import Iterable, Any

import asn1tools

log = logging.getLogger


def dump(direction: str, pdu: dict) -> None:
    class BytesSerializer(json.JSONEncoder):
        def default(self, o):
            if isinstance(o, bytes):
                return o.hex(" ")
            if isinstance(o, datetime):
                return o.strftime("%F_%T")
            return json.JSONEncoder.default(self, o)

    log(__name__).info(
        "Packet from %s\n%s", direction, json.dumps(pdu, indent=2, cls=BytesSerializer)
    )


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


def test_path(pdu: dict, keys: Iterable[Any], value: Any = None) -> bool:
    try:
        for k in keys:
            pdu = pdu[k]
        if value is not None:
            assert pdu == value
        return True
    except Exception:
        return False


async def forward_packet(
    supl_db: asn1tools.compiler.Specification,
    rrlp_db: asn1tools.compiler.Specification,
    lpp_db: asn1tools.compiler.Specification,
    direction: str,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    replacement: str,
) -> str:
    orig_imsi = replacement
    data = await asyncio.wait_for(reader.read(2), 30.0)
    if len(data) < 2:
        raise ConnectionAbortedError("closed")
    length = struct.unpack(">H", data)[0]
    data += await asyncio.wait_for(reader.read(length - 2), 1.0)
    pdu = supl_db.decode("ULP-PDU", data)

    if test_path(pdu, ["sessionID", "setSessionID", "setId", 0], "imsi"):
        orig_imsi = from_tbcd(pdu["sessionID"]["setSessionID"]["setId"][1])
        if replacement:
            pdu["sessionID"]["setSessionID"]["setId"] = ("imsi", to_tbcd(replacement))
    pretty_pdu = deepcopy(pdu)
    if test_path(pdu, ["message", 0], "msSUPLPOS") and test_path(
        pdu, ["message", 1, "posPayLoad", 0], "rrlpPayload"
    ):
        rrlp = pdu["message"][1]["posPayLoad"][1]
        pretty_pdu["message"][1]["posPayLoad"] = (
            "rrlpPayload",
            rrlp_db.decode("PDU", rrlp),
        )
    if (
        test_path(pdu, ["message", 0], "msSUPLPOS")
        and test_path(pdu, ["message", 1, "posPayLoad", 0], "ver2-PosPayLoad-extension")
        and test_path(pdu, ["message", 1, "posPayLoad", 1, "lPPPayload"])
    ):
        lpp = pdu["message"][1]["posPayLoad"][1]["lPPPayload"]
        pretty_pdu["message"][1]["posPayLoad"] = (
            "lPPPayload",
            list(map(lambda x: lpp_db.decode("LPP-Message", x), lpp)),
        )
    if test_path(pdu, ["message", 1, "position", "positionEstimate"]):
        pos = pdu["message"][1]["position"]["positionEstimate"]
        pretty_pos = pretty_pdu["message"][1]["position"]["positionEstimate"]
        pretty_pos["latitude"] = pos["latitude"] * 90.0 / (2 << 22)
        pretty_pos["longitude"] = pos["longitude"] * 360.0 / (2 << 23)

    dump(direction, pretty_pdu)
    data = supl_db.encode("ULP-PDU", pdu)
    writer.write(data)
    await writer.drain()
    return orig_imsi


async def handle_connection(
    args: argparse.Namespace,
    supl_db: asn1tools.compiler.Specification,
    rrlp_db: asn1tools.compiler.Specification,
    lpp_db: asn1tools.compiler.Specification,
    creader: asyncio.StreamReader,
    cwriter: asyncio.StreamWriter,
) -> None:
    peer = cwriter.get_extra_info("peername")
    log(__name__).info("Connection from %s:%d accepted", *peer)
    host, port = args.server.rsplit(":", 2)
    fake = "26201%10d" % randint(1011111111, 9999999999)
    ctx = None
    if args.tls:
        ctx = ssl.create_default_context()
        if args.tls_ignore_errors:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    if args.socks:
        sproxy = Proxy.from_url(args.socks)
        socks_sock = await sproxy.connect(dest_host=host, dest_port=int(port))
        sreader, swriter = await asyncio.open_connection(
            None, None, ssl=ctx, sock=socks_sock, server_hostname=host
        )
    else:
        sreader, swriter = await asyncio.open_connection(host, int(port), ssl=ctx)
    try:
        while True:
            orig_imsi = await forward_packet(
                supl_db, rrlp_db, lpp_db, "mobile", creader, swriter, fake
            )
            if orig_imsi:
                log(__name__).info("Replacing imsi %s with %s", orig_imsi, fake)
            await forward_packet(
                supl_db, rrlp_db, lpp_db, "server", sreader, cwriter, orig_imsi
            )
    except (
        ConnectionError,
        asn1tools.codecs.OutOfDataError,
        asn1tools.codecs.EncodeError,
    ) as e:
        log(__name__).info("Client %s:%d went away: %s", *peer, e)
    except asyncio.exceptions.TimeoutError:
        log(__name__).warning("Timeout on reader")
    finally:
        cwriter.close()
        await cwriter.wait_closed()
        swriter.close()
        await swriter.wait_closed()
    log(__name__).info("Connection to %s:%d closed", *peer)


async def main(args: argparse.Namespace) -> None:
    ulp_files = glob.glob(os.path.join(args.grammar, "supl-*.asn"))
    rrlp_files = glob.glob(os.path.join(args.grammar, "rrlp-*.asn"))
    lpp_files = glob.glob(os.path.join(args.grammar, "lpp-*.asn"))
    supl_db = asn1tools.compile_files(ulp_files, "uper", cache_dir="cache")
    rrlp_db = asn1tools.compile_files(rrlp_files, "uper", cache_dir="cache")
    lpp_db = asn1tools.compile_files(lpp_files, "uper", cache_dir="cache")
    tcp_server = None
    tls_server = None
    try:
        if args.tcp_port:
            tcp_server = await asyncio.start_server(
                partial(handle_connection, args, supl_db, rrlp_db, lpp_db),
                "0.0.0.0",
                args.tcp_port,
                reuse_address=True,
            )
            log(__name__).info("Listening on TCP port %d", args.tcp_port)

        if args.tls_port:
            ssl_ctx = None
            if args.key and args.cert and args.tls_port:
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_ctx.load_cert_chain(args.cert, args.key)
            tls_server = await asyncio.start_server(
                partial(handle_connection, args, supl_db, rrlp_db, lpp_db),
                "0.0.0.0",
                args.tls_port,
                reuse_address=True,
                ssl=ssl_ctx,
            )
            log(__name__).info("Listening on TLS port %d", args.tls_port)

        forever: asyncio.Future = asyncio.Future()
        await asyncio.wait([forever])

    finally:
        if tcp_server:
            tcp_server.close()
            await tcp_server.wait_closed()
            log(__name__).info("TCP server closed")
        if tls_server:
            tls_server.close()
            await tls_server.wait_closed()
            log(__name__).info("TLS server closed")


parser = argparse.ArgumentParser(description="Supl Proxy")
parser.add_argument(
    "-s", "--server", help="SUPL server (host:port)", default="supl.google.com:7275"
)
parser.add_argument(
    "-v",
    "--tls_ignore_errors",
    action="store_true",
    help="ignore server TLS error",
    default=False,
)
parser.add_argument("--tls", action="store_true", help="server uses TLS", default=False)
parser.add_argument("-c", "--cert", help="proxy TLS certificate", default=None)
parser.add_argument("-k", "--key", help="proxy TLS keyfile", default=None)
parser.add_argument("-p", "--tcp_port", type=int, help="TCP port", default=None)
parser.add_argument("-t", "--tls_port", type=int, help="TLS port", default=None)
parser.add_argument("-o", "--socks", help="socks proxy address, if any")
parser.add_argument("-g", "--grammar", help="path to asn.1 grammar", default="asn1")
parser.add_argument(
    "-l", "--logfile", help="path to logfile", default="/tmp/supl-proxy.log"
)
args = parser.parse_args()


rfh = RotatingFileHandler(args.logfile, maxBytes=1 << 20, backupCount=5)
logging.basicConfig(
    handlers=[rfh],
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=logging.INFO,
)

try:
    asyncio.run(main(args))
except KeyboardInterrupt:
    pass
