try:
    import urlparse
except ImportError:
    # py3k
    from urllib import parse as urlparse

import json
import threading
import Queue

from requests import Session, ConnectionError

from .firebase_authenticator import Authenticator, FireAuth

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

    def __init__(self, apikey, project_id, email=None, password=None, signup_first=False):
        self.dsn = "https://{}.firebaseio.com".format(project_id)
        self.buffer = Queue.Queue()

        if email is not None and password is not None:
            self.session = Authenticator(apikey, email, password, signup_first)
        else:
            self.session = Session()

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

    def get(self, url, name, auth=True, params=None, headers=None, in_thread=False):
        """
        Synchronous GET request.
        """

        fireauth = FireAuth(self.session.idToken) \
            if auth and isinstance(self.session, Authenticator) \
            else None

        endpoint, params, headers = self.__prepare_request(url, name, params, headers)
        try:
            return self.session.get(endpoint, params=params, headers=headers, auth=fireauth)
        except ConnectionError, e:
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
            return self.session.put(endpoint, data=data, params=params,
                                    headers=headers, auth=fireauth)
        except ConnectionError, e:
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
            return self.session.post(endpoint, data=data, params=params,
                                     headers=headers, auth=fireauth)
        except ConnectionError, e:
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
            return self.session.patch(endpoint, data=data, params=params,
                                      headers=headers, auth=fireauth)
        except ConnectionError, e:
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
            return self.session.delete(endpoint, params=params, headers=headers, auth=fireauth)
        except ConnectionError, e:
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
