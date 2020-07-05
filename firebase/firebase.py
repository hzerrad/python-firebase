try:
    import urlparse
except ImportError:
    # py3k
    from urllib import parse as urlparse

import json
import threading
import Queue

from requests import Session
from requests.exceptions import ReadTimeout, ConnectionError

from .firebase_authenticator import Authenticator, FireAuth
from .firebase_listener import FirebaseListener

from threading import Event

from .jsonutil import JSONEncoder

__all__ = ['FirebaseApplication']


class FirebaseApplication(object):
    """
    Class that actually connects with the Firebase backend via HTTP calls.
    It fully implements the RESTful specifications defined by Firebase. Data
    is transmitted as in JSON format in both ways. This class needs a DSN value
    that defines the base URL of the backend, and if needed, authentication
    credentials are accepted and then are taken into consideration while
    constructing HTTP requests.

    There are also the corresponding asynchronous versions of each HTTP method.
    The async calls make use of the on-demand process pool defined under the
    module `async`.

    auth = FirebaseAuthenticator(API_TOKEN, 'firebase@firebase.com', 'firebase_password')
    firebase = FirebaseApplication('https://firebase.localhost', auth)

    That's all there is. Then you start connecting with the backend:

    By default, authenticating the request is optional. To send the authentication
    token with your requests, set auth=true

    example:
    json_dict = firebase.get('/users', '1', {'print': 'pretty'}, auth=True)
    print json_dict
    {'1': 'John Doe', '2': 'Jane Doe', ...}

    Async version is:
    firebase.get('/users', '1', {'print': 'pretty'}, callback=log_json_dict)

    The callback method is fed with the returning response.
    """
    NAME_EXTENSION = '.json'
    URL_SEPARATOR = '/'

    def __init__(self, apikey, project_id, email=None, password=None, logger=None, signup_first=False, timeout=4):
        self.dsn = "https://{}.firebaseio.com".format(project_id)
        self.logger = logger
        self.buffer = Queue.Queue()
        self.timeout = timeout
        self.event = Event()

        if email is not None and password is not None:
            self.session = Authenticator(apikey, email, password, logger, signup_first, timeout=timeout)
        else:
            self.session = Session()

    def __prepare_request(self, url, name, params, headers):
        """
        Prepare the request's url, headers and query strings.
        """
        if not name:
            name = ''

        params = params or {}

        headers = headers or {}
        endpoint = self._build_endpoint_url(url, name)

        return endpoint, params, headers

    def _build_endpoint_url(self, url, name=None):
        """
        Method that constructs a full url with the given url and the
        snapshot name.

        Example:
        full_url = _build_endpoint_url('/users', '1')
        full_url => 'http://firebase.localhost/users/1.json'
        """
        if not url.endswith(self.URL_SEPARATOR):
            url = url + self.URL_SEPARATOR
        if name is None:
            name = ''
        return '%s%s%s' % (urlparse.urljoin(self.dsn, url), name,
                           self.NAME_EXTENSION)

    @property
    def listener(self):
        return self.session.listener

    ##############################################################################
    #####                   A P I    R E Q U E S T S                         #####
    ##############################################################################
    def get(self, url, name, auth=True, params=None, headers=None, in_thread=False):
        """
        Synchronous GET request.
        """

        fireauth = FireAuth(self.session.idToken) \
            if auth and isinstance(self.session, Authenticator) \
            else None

        endpoint, params, headers = self.__prepare_request(url, name, params, headers)
        try:
            if self.logger is not None:
                shorturl = endpoint.split("?auth=", 1)
                self.logger.info("GET {}".format(shorturl))
            return self.session.get(endpoint, params=params, headers=headers, auth=fireauth)
        except (ConnectionError, ReadTimeout) as e:
            if not in_thread:
                raise e
            else:
                self.buffer.put(e)

    def put(self, url, name, data, auth=True, params=None, headers=None, in_thread=False):
        """
        Synchronous PUT request. There will be no returning output from
        the server, because the request will be made with ``silent``
        parameter. ``data`` must be a JSONable value.
        """
        assert name, 'Snapshot name must be specified'

        fireauth = FireAuth(self.session.idToken) \
            if auth and isinstance(self.session, Authenticator) \
            else None

        endpoint, params, headers = self.__prepare_request(url, name, params, headers)
        data = json.dumps(data, cls=JSONEncoder)

        try:
            if self.logger is not None:
                shorturl = endpoint.split("?auth=", 1)
                self.logger.info("PUT {}".format(shorturl))
            return self.session.put(endpoint, data=data, params=params,
                                    headers=headers, auth=fireauth)
        except (ConnectionError, ReadTimeout) as e:
            if not in_thread:
                raise e
            else:
                self.buffer.put(e)

    def post(self, url, data, auth=True, params=None, headers=None, in_thread=False):
        """
        Synchronous POST request. ``data`` must be a JSONable value.
        """
        fireauth = FireAuth(self.session.idToken) \
            if auth and isinstance(self.session, Authenticator) \
            else None

        endpoint, params, headers = self.__prepare_request(url, None, params, headers)
        data = json.dumps(data, cls=JSONEncoder)
        try:
            if self.logger is not None:
                shorturl = endpoint.split("?auth=", 1)
                self.logger.info("POST {}".format(shorturl))
            return self.session.post(endpoint, data=data, params=params,
                                     headers=headers, auth=fireauth)
        except (ConnectionError, ReadTimeout) as e:
            if not in_thread:
                raise e
            else:
                self.buffer.put(e)

    def patch(self, url, data, auth=True, params=None, headers=None, in_thread=False):
        """
        Synchronous POST request. ``data`` must be a JSONable value.
        """
        fireauth = FireAuth(self.session.idToken) \
            if auth and isinstance(self.session, Authenticator) \
            else None

        endpoint, params, headers = self.__prepare_request(url, None, params, headers)
        data = json.dumps(data, cls=JSONEncoder)

        try:
            if self.logger is not None:
                shorturl = endpoint.split("?auth=", 1)
                self.logger.info("PATCH {}".format(shorturl))
            return self.session.patch(endpoint, data=data, params=params,
                                      headers=headers, auth=fireauth)
        except (ConnectionError, ReadTimeout) as e:
            if not in_thread:
                raise e
            else:
                self.buffer.put(e)

    def delete(self, url, name, auth=True, params=None, headers=None, in_thread=False):
        """
        Synchronous DELETE request. ``data`` must be a JSONable value.
        """
        fireauth = FireAuth(self.session.idToken) \
            if auth and isinstance(self.session, Authenticator) \
            else None

        endpoint, params, headers = self.__prepare_request(url, name, params, headers)

        try:
            if self.logger is not None:
                shorturl = endpoint.split("?auth=", 1)
                self.logger.info("DELETE {}".format(shorturl))
            return self.session.delete(endpoint, params=params, headers=headers, auth=fireauth)
        except (ConnectionError, ReadTimeout) as e:
            if not in_thread:
                raise e
            else:
                self.buffer.put(e)

    # == ASYNC == #

    def async_get(self, url, name, auth=True, params=None, headers=None):
        thread = threading.Thread(target=self.get, args=(url, name, auth, params, headers, True))
        thread.start()
        return thread

    def async_put(self, url, name, data, auth=True, params=None, headers=None):
        thread = threading.Thread(target=self.put, args=(url, name, data, auth, params, headers, True))
        thread.start()
        return thread

    def async_post(self, url, data, auth=True, params=None, headers=None):
        thread = threading.Thread(target=self.post, args=(url, data, auth, params, headers, True))
        thread.start()
        return thread

    def async_patch(self, url, data, auth=True, params=None, headers=None):
        thread = threading.Thread(target=self.patch, args=(url, data, auth, params, headers, True))
        thread.start()
        return thread

    def async_delete(self, url, name, auth=True, params=None, headers=None):
        thread = threading.Thread(target=self.delete, args=(url, name, auth, params, headers, True))
        thread.start()
        return thread

    ##############################################################################
    #####                S T R E A M     L I S T E N E R                     #####
    ##############################################################################

    def subscribe(self, url, callback):
        """
            subscribes a listener to the passed URL

            Parameters:
                url: string
                    shortened url to the path
                callback: function
                    a function called upon each event

        """
        if self.listener is not None and self.listener.isAlive():
            self.listener.stop()

        endpoint = self._build_endpoint_url(url)
        self.event.set()

        try:
            assert isinstance(self.session, Authenticator)
            listener = FirebaseListener(endpoint, callback, event=self.event,
                                        token=self.session.idToken, logger=self.logger)
            if self.logger is not None:
                marker = "?auth="
                index = endpoint.find(marker)
                shorturl = endpoint[0:index]
                self.logger.info("Registered listener @ {}".format(shorturl))
            self.session.listener = listener
            return listener
        except AssertionError:
            listener = FirebaseListener(endpoint, callback, event=self.event, logger=self.logger)
            self.logger.info("Registered listener @ {}".format(listener.url))
            return listener




