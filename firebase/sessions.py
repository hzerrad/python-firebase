import requests
from datetime import datetime


class Session(requests.Session):
    """
    A custom wrapper of Python requests that stores sessions and tracks authentication tokens expiry.
    """

    def __init__(self, timeout=60):
        super(Session, self).__init__()
        self.timeout = timeout
        self.headers.update({'Content-type': 'application/json'})
        self.token_ttl = None

    def set_timeout(self, timeout):
        self.timeout = timeout

    def update_token_ttl(self):
        self.token_ttl = datetime.utcnow()
