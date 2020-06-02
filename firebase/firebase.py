try:
    import urlparse
except ImportError:
    # py3k
    from urllib import parse as urlparse

import json

from .firebase_authenticator import Authenticator
from .sessions import Session

from .multiprocess_pool import process_pool
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

    def __init__(self, apikey, app_name, email=None, password=None, signup_first=False):

        self.dsn = "https://{}.firebaseio.com".format(app_name)
        self.session = Session()
        self.auth = False

        if email is not None and password is not None:
            self.__authenticator = Authenticator(apikey, email, password, self.session, signup_first)
            self.auth = True

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

    def get(self, url, name, auth=True, params=None, headers=None, connection=None):
        """
        Synchronous GET request.
        """
        if self.auth is False:
            auth = False

        endpoint, params, headers = self.__prepare_request(url, name, auth, params, headers)
        return self.session.get(endpoint, params=params, headers=headers)

    def get_async(self, url, name, auth=True, callback=None, params=None, headers=None):
        """
        Asynchronous GET request with the process pool.
        """
        if self.auth is False:
            auth = False

        args = self.__prepare_request(url, name, auth, params, headers)

        process_pool.apply_async(self.session.get,
                                 args=args, callback=callback)

    def put(self, url, name, data, auth=True, params=None, headers=None, connection=None):
        """
        Synchronous PUT request. There will be no returning output from
        the server, because the request will be made with ``silent``
        parameter. ``data`` must be a JSONable value.
        """
        if self.auth is False:
            auth = False

        assert name, 'Snapshot name must be specified'
        endpoint, params, headers = self.__prepare_request(url, name, auth, params, headers)
        data = json.dumps(data, cls=JSONEncoder)

        return self.session.put(endpoint, data=data, params=params, headers=headers)

    def put_async(self, url, name, data, auth=True, callback=None, params=None, headers=None):
        """
        Asynchronous PUT request with the process pool.
        """
        if self.auth is False:
            auth = False

        endpoint, params, headers = self.__prepare_request(url, name, auth, params, headers)
        data = json.dumps(data, cls=JSONEncoder)
        process_pool.apply_async(self.session.put,
                                 args=(endpoint, data, params, headers),
                                 callback=callback)

    def post(self, url, data, auth=True, params=None, headers=None, connection=None):
        """
        Synchronous POST request. ``data`` must be a JSONable value.
        """
        if self.auth is False:
            auth = False

        endpoint, params, headers = self.__prepare_request(url, None, auth, params, headers)
        data = json.dumps(data, cls=JSONEncoder)
        return self.session.post(endpoint, data=data, params=params, headers=headers)

    def post_async(self, url, data, auth=True, callback=None, params=None, headers=None):
        """
        Asynchronous POST request with the process pool.
        """
        if self.auth is False:
            auth = False

        endpoint, params, headers = self.__prepare_request(url, None, auth, params, headers)
        data = json.dumps(data, cls=JSONEncoder)
        process_pool.apply_async(self.session.post,
                                 args=(endpoint, data, params, headers),
                                 callback=callback)

    def patch(self, url, data, auth=True, params=None, headers=None, connection=None):
        """
        Synchronous POST request. ``data`` must be a JSONable value.
        """
        if self.auth is False:
            auth = False

        endpoint, params, headers = self.__prepare_request(url, None, auth, params, headers)
        data = json.dumps(data, cls=JSONEncoder)
        return self.session.patch(endpoint, data=data, params=params, headers=headers)

    def patch_async(self, url, data, auth=True, callback=None, params=None, headers=None):
        """
        Asynchronous PATCH request with the process pool.
        """
        if self.auth is False:
            auth = False

        endpoint, params, headers = self.__prepare_request(url, None, auth, params, headers)
        data = json.dumps(data, cls=JSONEncoder)
        process_pool.apply_async(self.session.patch,
                                 args=(endpoint, data, params, headers),
                                 callback=callback)

    def delete(self, url, name, auth=True, params=None, headers=None, connection=None):
        """
        Synchronous DELETE request. ``data`` must be a JSONable value.
        """
        if self.auth is False:
            auth = False

        endpoint, params, headers = self.__prepare_request(url, name, auth, params, headers)
        return self.session.delete(endpoint, params=params, headers=headers, connection=connection)

    def delete_async(self, url, name, auth=True, callback=None, params=None, headers=None):
        """
        Asynchronous DELETE request with the process pool.
        """
        if self.auth is False:
            auth = False

        args = self.__prepare_request(url, name, auth, params, headers)
        process_pool.apply_async(self.session.delete,
                                 args=args, callback=callback)

    def __prepare_request(self, url, name, auth, params, headers):
        """
        Prepare the request's url, headers and query strings.
        """
        if not name:
            name = ''
        params = params or {}
        if auth:
            assert self.__authenticator is not None, "NO_AUTH"
            params['auth'] = self.__authenticator.idToken
        headers = headers or {}
        endpoint = self._build_endpoint_url(url, name)

        return endpoint, params, headers
