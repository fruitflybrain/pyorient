__author__ = 'Ostico <ostico@gmail.com>'

from .database import BaseMessage
from ..constants import FIELD_BYTE, FIELD_STRINGS, SHUTDOWN_OP
from ..utils import need_connected


#
# Shutdown
#
class ShutdownMessage(BaseMessage):

    def __init__(self, _orient_socket):
        super(ShutdownMessage, self).__init__(_orient_socket)

        self._user = ''
        self._pass = ''

        # order matters
        self._append((FIELD_BYTE, SHUTDOWN_OP))

    @need_connected
    def prepare(self, params=None):

        if isinstance(params, tuple) or isinstance(params, list):
            try:
                self._user = params[0]
                self._pass = params[1]
            except IndexError:
                # Use default for non existent indexes
                pass
        self._append((FIELD_STRINGS, [self._user, self._pass]))
        return super(ShutdownMessage, self).prepare()

    def fetch_response(self):
        return super(ShutdownMessage, self).fetch_response()

    def set_user(self, _user):
        self._user = _user
        return self

    def set_pass(self, _pass):
        self._pass = _pass
        return self
