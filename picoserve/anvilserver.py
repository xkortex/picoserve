#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
https://blog.anvileight.com/posts/simple-python-http-server/
"""
import os
import io
import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler

from loguru import logger


def arg_parser():
    import argparse

    parser = argparse.ArgumentParser(description="A simple backend for DVC")

    parser.add_argument(
        "-H", "--host", default="", action="store", type=str, help="Host to serve on"
    )
    parser.add_argument(
        "-P", "--port", default=4223, action="store", type=int, help="Port to serve on"
    )
    parser.add_argument(
        "-K",
        "--key",
        default=None,
        action="store",
        type=str,
        help="Path to SSL key file",
    )
    parser.add_argument(
        "-C",
        "--cert",
        default=None,
        action="store",
        type=str,
        help="Path to SSL cert file",
    )
    parser.add_argument(
        "-w",
        "--workdir",
        default=os.getcwd(),
        action="store",
        type=str,
        help="workdir to serve from",
    )

    return parser


def main():
    args = arg_parser().parse_args()
    logger.debug(args)
    addr = (args.host, args.port)

    logger.info("Starting httpd on {}...".format(addr))

    httpd = HTTPServer(addr, BaseHTTPRequestHandler)

    if args.key or args.cert:
        if not args.key and args.cert:
            raise RuntimeError("Must specify both --key and --cert")
        if not os.path.isfile(args.key):
            raise FileNotFoundError("--key is not a file: {}".format(args.key))
        if not os.path.isfile(args.cert):
            raise FileNotFoundError("--cert is not a file: {}".format(args.cert))

        logger.info("Using key/cert file: {} / {}".format(args.key, args.cert))
        httpd.socket = ssl.wrap_socket(
            httpd.socket, keyfile=args.key, certfile=args.cert, server_side=True
        )
        logger.debug("Socket wrapped")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopping httpd...\n")


if __name__ == "__main__":
    main()
