import threading
import requests
import socket
import time


class FirebaseListener(threading.Thread):
    def __init__(self, url, callback, event=None, token=None, logger=None):
        super(FirebaseListener, self).__init__()
        self.daemon = True
        self.url = url
        self.callback = callback
        self.event = event
        self.__token = token
        self.logger = logger
        self.is_asleep = False
        if token:
            url += "?auth={}".format(token)
        try:
            self.listener = requests.get(url,
                                         headers={'Connection': "keep-alive", "Accept": "text/event-stream"},
                                         stream=True)
        except requests.ConnectionError:
            if self.logger is not None:
                self.logger.error("Listener: Could not connect to Firebase.")

        if logger is not None:
            logger.info("Listener launched @ {}".format(self.name))

    def __parser(self):
        """
        Parses the messages returned by Firebase Stream
        """
        event = dict()
        counter = 0
        try:
            for msg in self.listener.iter_lines(1):
                if msg:
                    key, value = msg.split(":", 1)
                    event[key.strip()] = value.strip()
                    event[counter] = value.strip()
                    counter += 1
                else:
                    if event:
                        yield event
                    event = dict()
                    counter = 0
        except ValueError:
            if self.logger is not None:
                self.logger.error("Listener: invalid message format.",
                                  exc_info=True)
            raise requests.exceptions.ChunkedEncodingError
        except requests.exceptions.StreamConsumedError:
            if self.logger is not None:
                self.logger.error("Listener: The content of this stream has already been consumed.",
                                  exc_info=True)
            raise requests.exceptions.ChunkedEncodingError

    def run(self):
        while True:
            events = self.__parser()
            try:
                for msg in events:
                    if msg['event'] == 'put' or msg['event'] == 'patch':
                        self.callback(msg)
                    if self.logger is not None:
                        self.logger.info("{}\n{}".format(self.name, msg))

                    if msg['event'] == 'auth_revoked':
                        if self.logger is not None:
                            self.logger.warning("auth token expired, listener will sleep")
                        else:
                            print "[WARN]: auth token expired, listener will sleep"
                        self.event.clear()
                        break
            except requests.exceptions.ChunkedEncodingError:
                if self.logger is not None:
                    self.logger.warning("Listener will be put to sleep.")
                if not self.is_asleep:
                    self.event.clear()

            if not self.event.is_set():
                if self.logger is not None:
                    self.logger.info("Listener @{} is asleep.".format(self.name))
                else:
                    print "Listener @{} is asleep.".format(self.name)
                self.is_asleep = True
                self.event.wait()
                self.is_asleep = False
                if self.logger is not None:
                    self.logger.info("Listener @{} is awake.".format(self.name))
                else:
                    print "Listener @{} is awake.".format(self.name)
                time.sleep(1)

            else:
                self.is_asleep = True
                if self.logger is not None:
                    self.logger.info("Listener @{} is terminated".format(self.name))
                else:
                    print "Listener @{} is terminated.".format(self.name)
                break

    def sleep(self):
        """
        Puts the listener to sleep.
        """
        if not self.is_asleep:
            self.event.clear()
            self.stop()

    def awaken(self, token=None):
        """
        Awakens the listener.
        """
        if self.is_asleep:
            if token:
                self.renew(token)
            else:
                self.renew(self.__token)
        else:
            if self.logger is not None:
                self.logger.warning('Listener is already awake. Ignoring awaken() call.')

    def renew(self, token):
        """
        Renews the authentication token.
        """
        if not self.is_asleep:
            self.sleep()
        url = self.url + "?auth={}".format(token)
        try:
            self.listener = requests.get(url,
                                         headers={'Connection': "keep-alive", "Accept": "text/event-stream"},
                                         stream=True)
            self.event.set()
            return True
        except (requests.ConnectionError, requests.exceptions.ReadTimeout), e:
            if self.logger is not None:
                self.logger.warning(
                    "Failed registering listener with Firebase.\nReason: {}".format(e.__str__())
                )
            return False

    def stop(self):
        """
        Closes the socket.
        If called alone, it completely terminates the listener
        """
        try:
            s = socket.fromfd(self.listener.raw.fileno(), socket.AF_INET, socket.SOCK_STREAM)
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            self.logger.warning("Socket shutdown failed.")
