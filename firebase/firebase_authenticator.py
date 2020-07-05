import requests
import time
from requests.auth import AuthBase
from firebase_listener import FirebaseListener

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
    def __init__(self, apikey, email, password, logger=None, signup_first=False, timeout=15):
        # Session
        super(Authenticator, self).__init__()
        self.timeout = timeout
        self.headers.update({'Content-type': 'application/json'})
        self.listener = None
        self.logger = logger
        self.token_expiry = None
        self.__should_renew = False

        # User Info
        self.apikey = apikey
        self.localId = None
        self.email = email
        self.__password = password
        self.__signup_first = signup_first

        # Tokens
        self.idToken = None
        self.__refreshToken = None

    # Next methods are overridden from requests.Session
    # With the added ability to request a new auth token when necessary

    # Override
    def get(self, url, **kwargs):
        if time.time() > self.token_expiry:
            self.__refresh()
            self.__renew_listener()
            kwargs['auth'] = FireAuth(self.idToken)
            return super(Authenticator, self).get(url, timeout=self.timeout, **kwargs)
        else:
            if self.__should_renew:
                self.__should_renew = not self.__renew_listener()
            return super(Authenticator, self).get(url, timeout=self.timeout, **kwargs)

    # Override
    def post(self, url, data=None, json=None, **kwargs):
        if time.time() > self.token_expiry:
            self.__refresh()
            self.__should_renew = not self.__renew_listener()
            kwargs['auth'] = FireAuth(self.idToken)
            return super(Authenticator, self).post(url, data, json, timeout=self.timeout, **kwargs)
        else:
            if self.__should_renew:
                self.__should_renew = not self.__renew_listener()
            return super(Authenticator, self).post(url, data, json, timeout=self.timeout, **kwargs)

    # Override
    def put(self, url, data=None, **kwargs):
        if time.time() > self.token_expiry:
            self.__refresh()
            self.__renew_listener()
            kwargs['auth'] = FireAuth(self.idToken)
            return super(Authenticator, self).put(url, data, timeout=self.timeout, **kwargs)
        else:
            if self.__should_renew:
                self.__should_renew = not self.__renew_listener()
            return super(Authenticator, self).put(url, data, timeout=self.timeout, **kwargs)

    # Override
    def patch(self, url, data=None, **kwargs):
        if time.time() > self.token_expiry:
            self.__refresh()
            self.__renew_listener()
            kwargs['auth'] = FireAuth(self.idToken)
            return super(Authenticator, self).patch(url, timeout=self.timeout, **kwargs)
        else:
            if self.__should_renew:
                self.__should_renew = not self.__renew_listener()
            return super(Authenticator, self).patch(url, timeout=self.timeout, **kwargs)

    # Override
    def delete(self, url, **kwargs):
        if time.time() > self.token_expiry:
            self.__refresh()
            self.__renew_listener()
            kwargs['auth'] = FireAuth(self.idToken)
            return super(Authenticator, self).delete(url, timeout=self.timeout, **kwargs)
        else:
            if self.__should_renew:
                self.__should_renew = not self.__renew_listener()
            return super(Authenticator, self).delete(url, timeout=self.timeout, **kwargs)

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
            super(Authenticator, self).post(SIGNIN_ENDPOINT + self.apikey, json=data, timeout=15)
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

    def __renew_listener(self):
        assert isinstance(self.listener, FirebaseListener)
        if self.logger is not None:
            self.logger.info("New token acquired. Renewing listener.")
        else:
            print("New token acquired. Renewing listener.")
            self.listener.renew(self.idToken)

    def update_token_ttl(self):
        """
            Sets the expiry time before a new Firebase Token is requested
        """
        self.token_expiry = time.time() + 3400  # 200s failsafe measure


class FireAuth(AuthBase):
    """
        Injects the idToken into the request to authenticate it
    """

    def __init__(self, idToken):
        self.__idToken = idToken

    def __call__(self, r):
        r.prepare_url(r.url, {"auth": self.__idToken})
        return r
