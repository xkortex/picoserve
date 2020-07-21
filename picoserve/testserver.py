import hashlib
import os
import sys
import threading
from functools import partial
from http import HTTPStatus
from http.server import HTTPServer

from loguru import logger
from RangeHTTPServer import RangeRequestHandler


class TestRequestHandler(RangeRequestHandler):
    def __init__(self, *args, **kwargs):
        # NOTE: `directory` was introduced in 3.7
        if sys.version_info < (3, 7):
            self.directory = kwargs.pop("directory", None) or os.getcwd()
        super().__init__(*args, **kwargs)

    def translate_path(self, path):
        import urllib
        import posixpath

        # NOTE: `directory` was introduced in 3.7
        if sys.version_info < (3, 7):
            return super().translate_path(path)

        path = path.split("?", 1)[0]
        path = path.split("#", 1)[0]
        # Don't forget explicit trailing slash when normalizing. Issue17324
        trailing_slash = path.rstrip().endswith("/")
        try:
            path = urllib.parse.unquote(path, errors="surrogatepass")
        except UnicodeDecodeError:
            path = urllib.parse.unquote(path)
        path = posixpath.normpath(path)
        words = path.split("/")
        words = filter(None, words)
        path = self.directory
        for word in words:
            if os.path.dirname(word) or word in (os.curdir, os.pardir):
                # Ignore components that are not a simple file/directory name
                continue
            path = os.path.join(path, word)
        if trailing_slash:
            path += "/"
        return path

    def end_headers(self):
        # RangeRequestHandler only sends Accept-Ranges header if Range header
        # is present, see https://github.com/danvk/RangeHTTPServer/issues/23
        if not self.headers.get("Range"):
            self.send_header("Accept-Ranges", "bytes")

        # Add a checksum header
        file = self.translate_path(self.path)

        if not os.path.isdir(file) and os.path.exists(file):
            with open(file, 'rb') as fd:
                data = fd.read()
                checksum = hashlib.md5(data).hexdigest()
                self.send_header("Content-MD5", checksum)

        RangeRequestHandler.end_headers(self)

    def _chunks(self):
        while True:
            data = self.rfile.readline(65537)
            chunk_size = int(data[:-2], 16)
            if chunk_size == 0:
                return
            data = self.rfile.read(chunk_size)
            yield data
            self.rfile.read(2)

    def do_POST(self):
        chunked = self.headers.get("Transfer-Encoding", "") == "chunked"
        path = self.translate_path(self.path)
        logger.info(
            "POST request,\n Path: {}\n Out URI: {}\n Size: {}\n Headers:\n{}".format(
             str(self.path), path, "?", str(self.headers),
            )
        )
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fd:
                if chunked:
                    for chunk in self._chunks():
                        fd.write(chunk)
                else:
                    size = int(self.headers.get("Content-Length", 0))
                    fd.write(self.rfile.read(size))
        except OSError as e:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))
        self.send_response(HTTPStatus.OK)
        self.end_headers()


class StaticFileServer:
    _lock = threading.Lock()

    def __init__(self, directory, port=888):
        from functools import partial
        addr = ("localhost", port)
        logger.info("Starting on {}".format(addr))
        self._lock.acquire()
        self._httpd = HTTPServer(
            addr, partial(TestRequestHandler, directory=directory),
        )
        self._thread = None

    def __enter__(self):
        self._thread = threading.Thread(target=self._httpd.serve_forever)
        self._thread.daemon = True
        self._thread.start()
        return self._httpd

    def __exit__(self, *args):
        self._httpd.socket.close()
        self._httpd.shutdown()
        self._httpd.server_close()
        self._lock.release()


def gen_server(directory=None):
    from tests.utils.httpd import StaticFileServer

    directory = os.path.join(
        directory or os.getcwd(), "dvc_tmp"
    )  # os.fspath(tmp_path_factory.mktemp("http"))
    with StaticFileServer(directory=directory) as httpd:
        yield httpd


if __name__ == "__main__":
    # for out in gen_server():
    #     print('.')
    #     out.serve_forever()  # hax
    #     exit(0)
    port = 9878
    argd = {k: sys.argv[k] for k in range(len(sys.argv))}
    directory = os.path.join(
        argd.get(1, '') or os.getcwd(), "dvc_tmp"
    )
    addr = ("localhost", port)
    logger.info("Starting on {}".format(addr))
    httpd = HTTPServer(
            addr, partial(TestRequestHandler, directory=directory),
        )
    httpd.serve_forever()