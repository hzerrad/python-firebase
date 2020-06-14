import requests
import threading
import time
from requests.auth import AuthBase
from firebase_streaming import EventListener

URL_SEPARATOR = '/'
REFRESH_ENDPOINT = 'https://securetoken.googleapis.com/v1/token?key='
SIGNUP_ENDPOINT = 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key='
SIGNIN_ENDPOINT = 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key='

PROVIDERS_ENDPOINT = 'https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key='


class Authenticator(requests.Session):
    """
    Helper class that extends requests.Session to
    implements basic email/password Firebase authentication.

    Static Variables:
    -----------------
    REFRESH_ENDPOINT: string
        endpoint to refresh token upon expiry.
    SIGNUP_ENDPOINT: string
        signs up a new user using the passed email/password
    SIGNIN_ENPOINT: string
        signs an existing user in using the passed email/password
    """

    def __init__(self, apikey, email, password, logger=None, signup_first=False):
        # Session
        super(Authenticator, self).__init__()
        self.headers.update({'Content-type': 'application/json'})
        self.listener_pool = ListenerPool()
        self.token_expiry = None
        self.watcher = None

        # User Info
        self.apikey = apikey
        self.localId = None
        self.email = email
        self.__password = password
        self.__signup_first = signup_first

        # Tokens
        self.idToken = None
        self.__refreshToken = None
        self.start_watcher(logger)

    # Next methods are overridden from requests.Session
    # With the added ability to request a new auth token when necessary

    # Override
    def get(self, url, **kwargs):
        if time.time() > self.token_expiry:
            self.__refresh()
            self.listener_pool.renewAll(self.idToken)
            kwargs['auth'] = FireAuth(self.idToken)
            return super(Authenticator, self).get(url, **kwargs)

        else:
            return super(Authenticator, self).get(url, **kwargs)

    # Override
    def post(self, url, data=None, json=None, **kwargs):
        if time.time() > self.token_expiry:
            self.__refresh()
            self.listener_pool.renewAll(self.idToken)
            kwargs['auth'] = FireAuth(self.idToken)
            return super(Authenticator, self).post(url, data, json, **kwargs)
        else:
            return super(Authenticator, self).post(url, data, json, **kwargs)

    # Override
    def put(self, url, data=None, **kwargs):
        if time.time() > self.token_expiry:
            self.__refresh()
            self.listener_pool.renewAll(self.idToken)
            kwargs['auth'] = FireAuth(self.idToken)
            return super(Authenticator, self).put(url, data, **kwargs)
        else:
            return super(Authenticator, self).put(url, data, **kwargs)

    # Override
    def patch(self, url, data=None, **kwargs):
        if time.time() > self.token_expiry:
            self.__refresh()
            self.listener_pool.renewAll(self.idToken)
            kwargs['auth'] = FireAuth(self.idToken)
            return super(Authenticator, self).patch(url, **kwargs)
        else:
            return super(Authenticator, self).patch(url, **kwargs)

    # Override
    def delete(self, url, **kwargs):
        if time.time() > self.token_expiry:
            self.__refresh()
            self.listener_pool.renewAll(self.idToken)
            kwargs['auth'] = FireAuth(self.idToken)
            return super(Authenticator, self).delete(url, **kwargs)
        else:
            return super(Authenticator, self).delete(url, **kwargs)

    def authenticate(self):
        """
            Request an authentication token from Firebase.
                - Sets `idToken` and `refreshToken` if ok
                - Fails otherwise
        """
        if not self.email or not self.__password:
            data = {'returnSecureToken': True}
        else:
            if self.__signup_first:
                self.__signup()
                self.__signup_first = False

            data = {
                'email': self.email,
                'password': self.__password,
                'returnSecureToken': True
            }

        self.__set_tokens_or_fail(
            super(Authenticator, self).post(SIGNIN_ENDPOINT + self.apikey, json=data)
        )

    def __signup(self):
        """
            Sign up a new user.
                - Sets `idToken` and `refreshToken` if ok
                - Fails otherwise
        """
        assert self.email is not None
        assert self.__password is not None

        data = {
            'email': self.email,
            'password': self.__password,
            'returnSecureToken': True
        }

        self.__signup_first = False

        self.__set_tokens_or_fail(
            super(Authenticator, self).post(SIGNUP_ENDPOINT + self.apikey, json=data)
        )

    def __refresh(self):
        """
            Exchange a refresh token for a new ID token.
                - Sets `idToken` and `refreshToken` if ok
                - Fails otherwise

            Parameters:
            -----------
                refresh_token: string
                    Refresh token
        """
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': self.__refreshToken
        }

        self.__set_tokens_or_fail(
            super(Authenticator, self).post(REFRESH_ENDPOINT + self.apikey, json=data)
        )

    def __set_tokens_or_fail(self, response):
        """
        Sets idToken and refreshToken upon successful requests.

        Parameters:
            response: requests.Response
            Response sent by Firebase servers.
        """
        if response.ok:
            self.update_token_ttl()

            # Assign localId
            localId = 'localId' if 'localId' in response.json().keys() else 'user_id'
            self.localId = response.json()[localId]

            # Assign idToken
            idToken = 'idToken' if 'idToken' in response.json().keys() else 'id_token'
            self.idToken = response.json()[idToken]

            # Assign RefreshToken
            refreshToken = 'refreshToken' if 'refreshToken' in response.json().keys() else 'refresh_token'
            self.__refreshToken = response.json()[refreshToken]
        else:
            response.raise_for_status()

    def update_token_ttl(self):
        """
            Sets the expiry time before a new Firebase Token is requested
        """
        self.token_expiry = time.time() + 3550

    def start_watcher(self, logger):
        self.watcher = _Watcher(self, logger)
        self.watcher.setDaemon(True)
        self.watcher.start()

    def stop_watcher(self):
        if self.watcher.isAlive():
            self.watcher.stop()


class FireAuth(AuthBase):
    """
        Injects the idToken into the request to authenticate it
    """

    def __init__(self, idToken):
        self.__idToken = idToken

    def __call__(self, r):
        r.prepare_url(r.url, {"auth": self.__idToken})
        return r


class ListenerPool(dict):
    """
    Simple dictionary that holds listeners
    with the ability to auto-renew
    """
    def __init__(self):
        super(ListenerPool, self).__init__()

    def renewAll(self, authKey=None):
        ListenerPool.renew(self, authKey)

    def renewByMarker(self, url_marker, authKey=None):
        marked = {k: v for k, v in self if url_marker in k}
        ListenerPool.renew(marked, authKey)

    @staticmethod
    def renew(listener_pool, authKey=None):
        for url, listener in listener_pool.items():
            if listener.remote_thread.isAlive():
                listener.stop()
            del listener_pool[url]
            marker = "?auth="
            index = url.find(marker)
            if index > -1 and authKey is not None:
                url = url[0:index] + "?auth={}".format(authKey)
            listener = EventListener(url, listener.function)
            listener.start()
            listener_pool[url] = listener


def connected():
    try:
        requests.get(SIGNIN_ENDPOINT)
        return True
    except requests.ConnectionError:
        return False


class _Watcher(threading.Thread):
    """
        Daemon that constantly watches listener threads in the background.
    """
    def __init__(self, session, logger=None):
        self.session = session
        self.logger = logger
        super(_Watcher, self).__init__()

    def logInfo(self, msg):
        if self.logger is not None:
            self.logger.info(msg)
        else:
            print "[INFO]: " + msg

    def logDebug(self, msg):
        if self.logger is not None:
            self.logger.debug(msg)
        else:
            print "[DEBUG]: " + msg

    def logError(self, msg):
        if self.logger is not None:
            self.logger.error(msg)
        else:
            print "[ERROR]: " + msg

    def run(self):
        self.logInfo("Watcher daemon started.")

        while True:
            if not connected():
                for _, listener in self.session.listener_pool.items():
                    if listener.remote_thread.isAlive():
                        self.logInfo("No internet connection detected. Stopping listener @{}"
                                     .format(listener.remote_thread.getName()))
                        listener.stop()
                time.sleep(5)
                continue

            if self.session.token_expiry > time.time():
                for url, listener in self.session.listener_pool.items():
                    assert isinstance(listener, EventListener)
                    if not listener.remote_thread.isAlive():
                        self.logInfo(listener.remote_thread.getName() + " perished. Restarting.")
                        listener = EventListener(url, listener.function)
                        listener.start()
                        self.session.listener_pool[url] = listener
            time.sleep(5)
