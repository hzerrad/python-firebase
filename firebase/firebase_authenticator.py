import requests


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

    def __init__(self, apikey, email, password, signup_first=False):
        self.apikey = apikey
        self.email = email
        self.__password = password
        self.__signup_first = signup_first

    def authenticate(self):
        """
            Request an authentication token from Firebase.

            Returns:
            --------
            requests.Response

            Server-side response to the request.
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

        res = requests.post(Authenticator.SIGNIN_ENDPOINT + self.apikey, json=data)
        assert res.status_code == 200, res.json()['error']['message']
        return res

    def refresh(self, refresh_token):
        """
            Exchange a refresh token for a new ID token.

            Parameters:
            -----------
                refresh_token: string
                    Refresh token

            Returns:
            ________
                requests.Response

                Server-side response to the request.
        """
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        }

        res = requests.post(Authenticator.REFRESH_ENDPOINT + self.apikey, json=data)
        assert res.status_code == 200, res.json()['error']['message']
        return res

    def __signup(self):
        """
            Sign up a new user.
        """
        assert self.email is not None
        assert self.__password is not None

        data = {
            'email': self.email,
            'password': self.__password,
            'returnSecureToken': True
        }

        self.__signup_first = False
        res = requests.post(Authenticator.SIGNUP_ENDPOINT + self.apikey, json=data)

        assert res.status_code == 200, res.json()['error']['message']

        return res
