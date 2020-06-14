# adapted from firebase/EventSource-Examples/python/chat.py by Shariq Hashme

from sseclient import SSEClient

import json
import threading
import socket
from urllib3.exceptions import ProtocolError
import ast
from requests import HTTPError


def json_to_dict(response):
    return ast.literal_eval(json.dumps(response))


class ClosableSSEClient(SSEClient):

    def __init__(self, *args, **kwargs):
        self.should_connect = True
        super(ClosableSSEClient, self).__init__(*args, **kwargs)

    def _connect(self):
        if self.should_connect:
            super(ClosableSSEClient, self)._connect()
        else:
            raise StopIteration()

    def close(self):
        self.should_connect = False
        self.retry = 0
        try:
            self.resp.raw._fp.fp._sock.shutdown(socket.SHUT_RDWR)
            self.resp.raw._fp.fp._sock.close()
        except AttributeError:
            pass


class RemoteThread(threading.Thread):

    def __init__(self, parent, URL, function):
        self.sse = ClosableSSEClient(URL, chunk_size=1)
        self.function = function
        self.URL = URL
        self.parent = parent
        super(RemoteThread, self).__init__()

    def run(self):
        try:
            for msg in self.sse:
                try:
                    msg_test = json.loads(msg.data)
                    if msg_test is None:  # keep-alives
                        continue
                    msg_data = json_to_dict(msg.data)
                    self.function((msg.event, msg_data))
                except ValueError:
                    print msg
        except socket.error:
            pass  # this can happen when we close the stream
        except (HTTPError, KeyboardInterrupt, ProtocolError):
            self.close()

    def close(self):
        if self.sse:
            self.sse.close()


class EventListener:

    def __init__(self, URL, function):
        self.cache = {}
        self.URL = URL
        self.function = function
        self.remote_thread = RemoteThread(self, URL, function)

    def start(self):
        self.remote_thread.start()

    def stop(self):
        self.remote_thread.close()
        self.remote_thread.join()

    def wait(self):
        self.remote_thread.join()
