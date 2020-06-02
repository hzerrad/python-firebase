class Authenticator:
    """
    Helper class that implements basic email/password Firebase authentication.

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

    def __init__(self, apikey, email, password, session, signup_first=False):
        # identity
        self.apikey = apikey
        self.localId = None
        self.email = email
        self.__password = password
        self.__signup_first = signup_first

        # Session
        self.__session = session
        self.idToken = None
        self.refreshToken = None

        # authenticate
        self.__authenticate()

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
            self.__session.post(Authenticator.SIGNIN_ENDPOINT + self.apikey, json=data)
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
            self.__session.post(Authenticator.SIGNUP_ENDPOINT + self.apikey, json=data)
        )

    def __set_tokens_or_fail(self, response):
        """
        Sets idToken and refreshToken upon successful requests.

        Parameters:
            response: requests.Response
            Response sent by Firebase servers.
        """
        if response.ok:
            self.__session.update_token_ttl()
            self.localId = response.json()['localId']
            self.idToken = response.json()['idToken']
            self.refreshToken = response.json()['refreshToken']
        else:
            response.raise_for_status()

    def refresh(self, refresh_token):
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
            'refresh_token': refresh_token
        }

        self.__set_tokens_or_fail(
            self.__session.post(Authenticator.REFRESH_ENDPOINT + self.apikey, json=data)
        )
