try:
    import urlparse
except ImportError:
    # py3k
    from urllib import parse as urlparse

import json

from .firebase_authenticator import Authenticator
from .decorators import http_connection

from .multiprocess_pool import process_pool
from .jsonutil import JSONEncoder

__all__ = ['FirebaseAuthenticator', 'FirebaseApplication']


@http_connection(60)
def make_get_request(url, params, headers, connection):
    """
    Helper function that makes an HTTP GET request to the given firebase
    endpoint. Timeout is 60 seconds.
    `url`: The full URL of the firebase endpoint (DSN appended.)
    `params`: Python dict that is appended to the URL like a querystring.
    `headers`: Python dict. HTTP request headers.
    `connection`: Predefined HTTP connection instance. If not given, it
    is supplied by the `decorators.http_connection` function.

    The returning value is a Python dict deserialized by the JSON decoder. However,
    if the status code is not 2x or 403, an requests.HTTPError is raised.

    connection = connection_pool.get_available_connection()
    response = make_get_request('http://firebase.localhost/users', {'print': silent'},
                                {'X_FIREBASE_SOMETHING': 'Hi'}, connection)
    response => {'1': 'John Doe', '2': 'Jane Doe'}
    """
    timeout = getattr(connection, 'timeout')
    response = connection.get(url, params=params, headers=headers, timeout=timeout)
    if response.ok or response.status_code == 403:
        return response.json() if response.content else None
    else:
        response.raise_for_status()


@http_connection(60)
def make_put_request(url, data, params, headers, connection):
    """
    Helper function that makes an HTTP PUT request to the given firebase
    endpoint. Timeout is 60 seconds.
    `url`: The full URL of the firebase endpoint (DSN appended.)
    `data`: JSON serializable dict that will be stored in the remote storage.
    `params`: Python dict that is appended to the URL like a querystring.
    `headers`: Python dict. HTTP request headers.
    `connection`: Predefined HTTP connection instance. If not given, it
    is supplied by the `decorators.http_connection` function.

    The returning value is a Python dict deserialized by the JSON decoder. However,
    if the status code is not 2x or 403, an requests.HTTPError is raised.

    connection = connection_pool.get_available_connection()
    response = make_put_request('http://firebase.localhost/users',
                                '{"1": "Ozgur Vatansever"}',
                                {'X_FIREBASE_SOMETHING': 'Hi'}, connection)
    response => {'1': 'Ozgur Vatansever'} or {'error': 'Permission denied.'}
    """
    timeout = getattr(connection, 'timeout')
    response = connection.put(url, data=data, params=params, headers=headers,
                              timeout=timeout)
    if response.ok or response.status_code == 403:
        return response.json() if response.content else None
    else:
        response.raise_for_status()


@http_connection(60)
def make_post_request(url, data, params, headers, connection):
    """
    Helper function that makes an HTTP POST request to the given firebase
    endpoint. Timeout is 60 seconds.
    `url`: The full URL of the firebase endpoint (DSN appended.)
    `data`: JSON serializable dict that will be stored in the remote storage.
    `params`: Python dict that is appended to the URL like a querystring.
    `headers`: Python dict. HTTP request headers.
    `connection`: Predefined HTTP connection instance. If not given, it
    is supplied by the `decorators.http_connection` function.

    The returning value is a Python dict deserialized by the JSON decoder. However,
    if the status code is not 2x or 403, an requests.HTTPError is raised.

    connection = connection_pool.get_available_connection()
    response = make_put_request('http://firebase.localhost/users/',
       '{"Ozgur Vatansever"}', {'X_FIREBASE_SOMETHING': 'Hi'}, connection)
    response => {u'name': u'-Inw6zol_2f5ThHwVcSe'} or {'error': 'Permission denied.'}
    """
    timeout = getattr(connection, 'timeout')
    response = connection.post(url, data=data, params=params, headers=headers,
                               timeout=timeout)
    if response.ok or response.status_code == 403:
        return response.json() if response.content else None
    else:
        response.raise_for_status()


@http_connection(60)
def make_patch_request(url, data, params, headers, connection):
    """
    Helper function that makes an HTTP PATCH request to the given firebase
    endpoint. Timeout is 60 seconds.
    `url`: The full URL of the firebase endpoint (DSN appended.)
    `data`: JSON serializable dict that will be stored in the remote storage.
    `params`: Python dict that is appended to the URL like a querystring.
    `headers`: Python dict. HTTP request headers.
    `connection`: Predefined HTTP connection instance. If not given, it
    is supplied by the `decorators.http_connection` function.

    The returning value is a Python dict deserialized by the JSON decoder. However,
    if the status code is not 2x or 403, an requests.HTTPError is raised.

    connection = connection_pool.get_available_connection()
    response = make_put_request('http://firebase.localhost/users/1',
       '{"Ozgur Vatansever"}', {'X_FIREBASE_SOMETHING': 'Hi'}, connection)
    response => {'Ozgur Vatansever'} or {'error': 'Permission denied.'}
    """
    timeout = getattr(connection, 'timeout')
    response = connection.patch(url, data=data, params=params, headers=headers,
                                timeout=timeout)
    if response.ok or response.status_code == 403:
        return response.json() if response.content else None
    else:
        response.raise_for_status()


@http_connection(60)
def make_delete_request(url, params, headers, connection):
    """
    Helper function that makes an HTTP DELETE request to the given firebase
    endpoint. Timeout is 60 seconds.
    `url`: The full URL of the firebase endpoint (DSN appended.)
    `params`: Python dict that is appended to the URL like a querystring.
    `headers`: Python dict. HTTP request headers.
    `connection`: Predefined HTTP connection instance. If not given, it
    is supplied by the `decorators.http_connection` function.

    The returning value is NULL. However, if the status code is not 2x or 403,
    an requests.HTTPError is raised.

    connection = connection_pool.get_available_connection()
    response = make_put_request('http://firebase.localhost/users/1',
                                {'X_FIREBASE_SOMETHING': 'Hi'}, connection)
    response => NULL or {'error': 'Permission denied.'}
    """
    timeout = getattr(connection, 'timeout')
    response = connection.delete(url, params=params, headers=headers, timeout=timeout)
    if response.ok or response.status_code == 403:
        return response.json() if response.content else None
    else:
        response.raise_for_status()


class FirebaseAuthenticator(object):

    def __init__(self, apikey, email, password, signup_first=False):
        self.__authenticator = Authenticator(apikey, email, password, signup_first=signup_first)
        self.auth = self.__authenticator.authenticate()

    @property
    def idToken(self):
        return self.auth.json()['idToken']

    @property
    def refreshToken(self):
        return self.auth.json()['refreshToken']

    @property
    def localId(self):
        return self.auth.json()['localId']

    @property
    def email(self):
        return self.auth.json()['email']


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

    def __init__(self, app_name, authentication=None):

        self.dsn = "https://{}.firebaseio.com".format(app_name)
        self.authentication = authentication

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

    @http_connection(60)
    def get(self, url, name, auth=False, params=None, headers=None, connection=None):
        """
        Synchronous GET request.
        """
        endpoint, params, headers = self.__prepare_request(url, name, auth, params, headers)
        return make_get_request(endpoint, params, headers, connection=connection)

    def get_async(self, url, name, auth=False, callback=None, params=None, headers=None):
        """
        Asynchronous GET request with the process pool.
        """
        args = self.__prepare_request(url, name, auth, params, headers)

        process_pool.apply_async(make_get_request,
                                 args=args, callback=callback)

    @http_connection(60)
    def put(self, url, name, data, auth=False, params=None, headers=None, connection=None):
        """
        Synchronous PUT request. There will be no returning output from
        the server, because the request will be made with ``silent``
        parameter. ``data`` must be a JSONable value.
        """
        assert name, 'Snapshot name must be specified'
        endpoint, params, headers = self.__prepare_request(url, name, auth, params, headers)
        data = json.dumps(data, cls=JSONEncoder)
        return make_put_request(endpoint, data, params, headers,
                                connection=connection)

    def put_async(self, url, name, data, auth=False, callback=None, params=None, headers=None):
        """
        Asynchronous PUT request with the process pool.
        """
        endpoint, params, headers = self.__prepare_request(url, name, auth, params, headers)
        data = json.dumps(data, cls=JSONEncoder)
        process_pool.apply_async(make_put_request,
                                 args=(endpoint, data, params, headers),
                                 callback=callback)

    @http_connection(60)
    def post(self, url, data, auth=False, params=None, headers=None, connection=None):
        """
        Synchronous POST request. ``data`` must be a JSONable value.
        """
        endpoint, params, headers = self.__prepare_request(url, None, auth, params, headers)
        data = json.dumps(data, cls=JSONEncoder)
        return make_post_request(endpoint, data, params, headers,
                                 connection=connection)

    def post_async(self, url, data, auth=False, callback=None, params=None, headers=None):
        """
        Asynchronous POST request with the process pool.
        """
        endpoint, params, headers = self.__prepare_request(url, None, auth, params, headers)
        data = json.dumps(data, cls=JSONEncoder)
        process_pool.apply_async(make_post_request,
                                 args=(endpoint, data, params, headers),
                                 callback=callback)

    @http_connection(60)
    def patch(self, url, data, auth=False, params=None, headers=None, connection=None):
        """
        Synchronous POST request. ``data`` must be a JSONable value.
        """
        endpoint, params, headers = self.__prepare_request(url, None, auth, params, headers)
        data = json.dumps(data, cls=JSONEncoder)
        return make_patch_request(endpoint, data, params, headers,
                                  connection=connection)

    def patch_async(self, url, data, auth=False, callback=None, params=None, headers=None):
        """
        Asynchronous PATCH request with the process pool.
        """
        endpoint, params, headers = self.__prepare_request(url, None, auth, params, headers)
        data = json.dumps(data, cls=JSONEncoder)
        process_pool.apply_async(make_patch_request,
                                 args=(endpoint, data, params, headers),
                                 callback=callback)

    @http_connection(60)
    def delete(self, url, name, auth=False, params=None, headers=None, connection=None):
        """
        Synchronous DELETE request. ``data`` must be a JSONable value.
        """
        endpoint, params, headers = self.__prepare_request(url, name, auth, params, headers)
        return make_delete_request(endpoint, params, headers, connection=connection)

    def delete_async(self, url, name, auth=False, callback=None, params=None, headers=None):
        """
        Asynchronous DELETE request with the process pool.
        """
        args = self.__prepare_request(url, name, auth, params, headers)
        process_pool.apply_async(make_delete_request,
                                 args=args, callback=callback)

    def __prepare_request(self, url, name, auth, params, headers):
        """
        Prepare the request's url, headers and query strings.
        """
        if not name:
            name = ''
        params = params or {}
        if auth:
            assert self.authentication is not None, "NO_AUTH"
            params['auth'] = self.authentication.idToken
        headers = headers or {}
        endpoint = self._build_endpoint_url(url, name)

        return endpoint, params, headers
