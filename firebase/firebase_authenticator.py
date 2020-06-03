from requests import Session
from requests.auth import AuthBase
import time


class Authenticator(Session):
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
    REFRESH_ENDPOINT = 'https://securetoken.googleapis.com/v1/token?key='
    SIGNUP_ENDPOINT = 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key='
    SIGNIN_ENDPOINT = 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key='

    PROVIDERS_ENDPOINT = 'https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key='

    def __init__(self, apikey, email, password, signup_first=False, timeout=60):
        # Session
        super(Session, self).__init__()
        self.timeout = timeout
        self.headers.update({'Content-type': 'application/json'})
        self.token_expiry = None

        # User Info
        self.apikey = apikey
        self.localId = None
        self.email = email
        self.__password = password
        self.__signup_first = signup_first

        # Tokens
        self.idToken = None
        self.__refreshToken = None

        # authenticate
        self.__authenticate()

    def set_timeout(self, timeout):
        self.timeout = timeout

    def update_token_ttl(self):
        self.token_expiry = time.time() + 3600

    # Override
    def get(self, url, **kwargs):
        if time.time() > self.token_expiry:
            self.__refresh()
            kwargs['auth'] = FireAuth(self.idToken)
            super(Authenticator, self).get(url, **kwargs)

        else:
            super(Authenticator, self).get(url, **kwargs)

    # Override
    def post(self, url, data=None, json=None, **kwargs):
        if time.time() > self.token_expiry:
            self.__refresh()
            kwargs['auth'] = FireAuth(self.idToken)
            super(Authenticator, self).post(url, data, json, **kwargs)
        else:
            super(Authenticator, self).post(url, data, json, **kwargs)

    # Override
    def put(self, url, data=None, **kwargs):
        if time.time() > self.token_expiry:
            self.__refresh()
            kwargs['auth'] = FireAuth(self.idToken)
            super(Authenticator, self).put(url, data, **kwargs)
        else:
            super(Authenticator, self).put(url, data, **kwargs)

    # Override
    def patch(self, url, data=None, **kwargs):
        if time.time() > self.token_expiry:
            self.__refresh()
            kwargs['auth'] = FireAuth(self.idToken)
            super(Authenticator, self).patch(url, **kwargs)
        else:
            super(Authenticator, self).patch(url, **kwargs)

    # Override
    def delete(self, url, **kwargs):
        if time.time() > self.token_expiry:
            self.__refresh()
            kwargs['auth'] = FireAuth(self.idToken)
            super(Authenticator, self).delete(url, **kwargs)
        else:
            super(Authenticator, self).delete(url, **kwargs)

    def __authenticate(self):
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
            self.post(Authenticator.SIGNIN_ENDPOINT + self.apikey, json=data)
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
            self.post(Authenticator.SIGNUP_ENDPOINT + self.apikey, json=data)
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
            self.post(Authenticator.REFRESH_ENDPOINT + self.apikey, json=data)
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
            self.localId = response.json()['localId']
            self.idToken = response.json()['idToken']
            self.__refreshToken = response.json()['refreshToken']
        else:
            response.raise_for_status()


class FireAuth(AuthBase):
    """
        Injects the idToken into the request to authenticate it
    """

    def __init__(self, idToken):
        self.__idToken = idToken

    def __call__(self, r):
        r.prepare_url(r.url, {"auth": self.__idToken})
        return r
