#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Very simple HTTP server in python for logging requests and PUTing/POSTing files
Usage::
    ./server.py [<port>]
"""
import os
import io
import ssl
from loguru import logger
from http.server import SimpleHTTPRequestHandler, HTTPServer


class S(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def __init__(self, *args, directory=None, **kwargs):
        if directory is None:
            directory = os.getcwd()
        self.directory = directory
        super().__init__(*args, **kwargs)

    def _set_response(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):
        # import ipdb
        # ipdb.set_trace()
        f = self.send_head()  # type: io.BufferedReader
        logger.info(
            "GET request,\n Path:    %s\n Headers: \n%s\n",
            str(self.path),
            str(self.headers),
        )
        logger.info(f)
        logger.info(type(f))

        if f:
            try:
                logger.info("Copying file {}".format(self.path))
                self.copyfile(f, self.wfile)
            finally:
                f.close()
        # self._set_response()
        # self.wfile.write("GET request for {}".format(self.path).encode("utf-8"))

    def upload(self, reqtype="POST"):
        content_length = self.headers.get("Content-Length", None)
        pathspec = self.headers.get("filename", "")
        real_pathspec = pathspec or self.path
        out_uri = os.path.join(self.directory, os.path.relpath(real_pathspec, "/"))

        logger.info(
            "{} request,\n Path: {}\n Out URI: {}\n Size: {}\n Headers:\n{}".format(
                reqtype, str(self.path), out_uri, content_length, str(self.headers),
            )
        )
        if content_length is None:
            logger.warning("Content-Length is missing or zero")
            content_length = 0
        content_length = int(content_length)

        if not real_pathspec:
            self.send_response(400)
            self.end_headers()
            self.wfile.write("Bad path: {} ({})".format(real_pathspec, out_uri))
            return

        # import ipdb
        # ipdb.set_trace()

        body = self.rfile.read(content_length)  # <--- Gets the data itself
        # os.makedirs(os.path.dirname(out_uri), exist_ok=True)
        # with open(out_uri, "wb") as fp:
        #     fp.write(body)

        self.send_response(200)
        self.end_headers()
        response = io.BytesIO()
        response.write("{}".format(content_length).encode())
        self.wfile.write(response.getvalue())

    def do_POST(self):
        self.upload("POST")

    def do_PUT(self):
        self.upload("PUT")


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
        "-K", "--key", default=None, action="store", type=str, help="Path to SSL key file"
    )
    parser.add_argument(
        "-C", "--cert", default=None, action="store", type=str, help="Path to SSL cert file"
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
    server_class = HTTPServer
    handler_class = S
    logger.info("Starting httpd on {}...".format(addr))

    httpd = server_class(addr, handler_class)

    if args.key or args.cert:
        if not args.key and args.cert:
            raise RuntimeError('Must specify both --key and --cert')
        if not os.path.isfile(args.key):
            raise FileNotFoundError('--key is not a file: {}'.format(args.key))
        if not os.path.isfile(args.cert):
            raise FileNotFoundError('--cert is not a file: {}'.format(args.cert))

        logger.info("Using key/cert file: {} / {}".format(args.key, args.cert))
        httpd.socket = ssl.wrap_socket(httpd.socket,
                                       keyfile=args.key,
                                       certfile=args.cert, server_side=True)
        logger.debug("Socket wrapped")


    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopping httpd...\n")



if __name__ == "__main__":
    main()
