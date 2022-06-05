# -*- coding: utf-8 -*-
__author__ = 'Ostico <ostico@gmail.com>'

import struct
import sys

from pyorient import FIELD_BYTE, CONNECT_OP, FIELD_STRINGS, NAME, VERSION, FIELD_SHORT, SUPPORTED_PROTOCOL, \
    FIELD_STRING, FIELD_BOOLEAN, FIELD_INT
from pyorient.exceptions import PyOrientCommandException, PyOrientNullRecordException
from pyorient.orient import OrientSocket, OrientSerialization, PyOrientBadMethodCallException

from pyorient.constants import DB_OPEN_OP, DB_TYPE_DOCUMENT, DB_COUNT_RECORDS_OP, \
    FIELD_SHORT, FIELD_STRINGS, FIELD_BYTES, NAME, SUPPORTED_PROTOCOL, VERSION, FIELD_RECORD, FIELD_TYPE_LINK, \
    DB_TYPES, DB_CLOSE_OP, DB_EXIST_OP, STORAGE_TYPE_PLOCAL, STORAGE_TYPE_LOCAL, DB_CREATE_OP, FIELD_INT, \
    FIELD_STRING, FIELD_BYTE, FIELD_BOOLEAN, INT, SHORT, LONG, BOOLEAN, BYTE, BYTES, STRING, STRINGS, \
    RECORD, LINK, CHAR, DB_DROP_OP, DB_RELOAD_OP, DB_SIZE_OP, DB_LIST_OP, STORAGE_TYPES, FIELD_LONG
from pyorient.hexdump import hexdump
from pyorient.utils import need_connected, need_db_opened, is_debug_active, get_hash
from pyorient.otypes import OrientRecord, OrientCluster, OrientVersion, OrientRecordLink, OrientNode


#
# DB OPEN
#
# This is the first operation the client should call.
# It opens a database on the remote OrientDB Server.
# Returns the Session-Id to being reused for all the next calls and
# the list of configured clusters.
#
# Request: (driver-name:string)(driver-version:string)
#   (protocol-version:short)(client-id:string)(serialization-impl:string)
#   (database-name:string)(database-type:string)(user-name:string)(user-password:string)
#  Response:(session-id:int)(num-of-clusters:short)[(cluster-name:string)
#   (cluster-id:short)](cluster-config:bytes.md)(orientdb-release:string)
#
# client's driver-name as string. Example: "OrientDB Java client"
# client's driver-version as string. Example: "1.0rc8-SNAPSHOT"
# client's protocol-version as short. Example: 7
# client's client-id as string. Can be null for clients. In clustered configuration
#   is the distributed node ID as TCP host+port. Example: "10.10.10.10:2480"
# client's serialization-impl the serialization format required by the client.
# database-name as string. Example: "demo"
# database-type as string, can be 'document' or 'graph' (since version 8). Example: "document"
# user-name as string. Example: "admin"
# user-password as string. Example: "admin"
# cluster-config is always null unless you're running in a server clustered configuration.
# orientdb-release as string. Contains version of OrientDB release
#   deployed on server and optionally build number. Example: "1.4.0-SNAPSHOT (build 13)"
#
#


class BaseMessage(object):

    def __init__(self, sock=OrientSocket):
        """
        :type sock: OrientSocket
        """
        sock.get_connection()
        self._orientSocket = sock
        self._protocol = self._orientSocket.protocol
        self._session_id = self._orientSocket.session_id

        # handles token auth
        self._auth_token = self._orientSocket.auth_token
        self._request_token = True  # Tokens required as of OrientDB v3.1

        self._header = []
        """:type : list of [str]"""

        self._body = []
        """:type : list of [str]"""

        self._fields_definition = []
        """:type : list of [object]"""

        self._command = chr(0)
        self._db_opened = self._orientSocket.db_opened
        self._connected = self._orientSocket.connected

        self._node_list = []
        """:type : list of [OrientNode]"""

        self._serializer = None

        self._output_buffer = b''
        self._input_buffer = b''

        # callback function for async queries
        self._callback = None

        # callback for push received from the server
        self._push_callback = None

        self._need_token = True

        global in_transaction
        in_transaction = False

    def get_serializer(self):
        """
        Lazy return of the serialization, we retrive the type from the :class: `OrientSocket <pyorient.orient.OrientSocket>` object
        :return: an Instance of the serializer suitable for decoding or encoding
        """
        if self._orientSocket.serialization_type == OrientSerialization.Binary:
            return OrientSerialization.get_impl(self._orientSocket.serialization_type, self._orientSocket._props)

        else:
            return OrientSerialization.get_impl(self._orientSocket.serialization_type)

    def get_orient_socket_instance(self):
        return self._orientSocket

    def is_connected(self):
        return self._connected is True

    def database_opened(self):
        return self._db_opened

    def get_cluster_map(self):
        """:type : list of [OrientNode]"""
        return self._node_list

    def set_session_token(self, token=''):
        """
        :param token: Set the request to True to use the token authentication
        :type token: bool|string
        :return: self
        """
        if token != '' and token is not None:

            if type(token) is bool:
                self._request_token = token

            elif type(token) is str or type(token) is bytes:
                self._request_token = True
                self._auth_token = token
                self._db_opened = True
                self._connected = True
                self._update_socket_token()

        return self

    def get_session_token(self):
        """Retrieve the session token to reuse after."""
        return self._auth_token

    def _update_socket_id(self):
        """Force update of socket id from inside the class."""
        self._orientSocket.session_id = self._session_id
        return self

    def _update_socket_token(self):
        """Force update of socket token from inside the class."""
        self._orientSocket.auth_token = self._auth_token
        return self

    def _reset_fields_definition(self):
        self._fields_definition = []

    def prepare(self, *args):
        """
        #  Token authentication handling
        #  we must recognize ConnectMessage and DbOpenMessage messages
        """
        # session_id
        self._fields_definition.insert(1, (FIELD_INT, self._session_id))
        if self._need_token and self._request_token is True:
            self._fields_definition.insert(
                2, (FIELD_STRING, self._auth_token)
            )

        self._output_buffer = b''.join(
            self._encode_field(x) for x in self._fields_definition
        )
        return self

    def get_protocol(self):
        if self._protocol < 0:
            self._protocol = self._orientSocket.protocol
        return self._protocol

    def _token_refresh_check(self):
        """Token authentication handling.

        We must check for ConnectMessage and DbOpenMessage messages.
        """

        token_refresh = self._decode_field(FIELD_STRING)
        if token_refresh != b'':
            self._auth_token = token_refresh
            self._update_socket_token()

    def _decode_header(self):

        # read header's information
        # https://orientdb.org/docs/3.2.x/internals/Network-Binary-Protocol.html
        self._header = [
            self._decode_field(FIELD_BYTE),  # Success status of the request if succeeded or failed (0=OK, 1=ERROR)
            self._decode_field(FIELD_INT),  # 4 bytes: Session-Id (Integer)
        ]

        if not isinstance(self, (ConnectMessage, DbOpenMessage)) and self._request_token is True:
            self._token_refresh_check()

        # decode message errors and raise an exception
        if self._header[0] == 1:

            # Parse the error
            # The format is: [(1)(exception-class:string)(exception-message:string)]*(0)(serialized-exception:bytes)]
            exception_class = b""
            exception_message = b""

            more = self._decode_field(FIELD_BOOLEAN)

            while more:
                # read num bytes by the field definition
                exception_class += self._decode_field(FIELD_STRING)  # (exception-class:string)
                exception_message += self._decode_field(FIELD_STRING)  # (exception-message:string)
                more = self._decode_field(FIELD_BOOLEAN)

                if self.get_protocol() > 18:  # > 18 1.6-snapshot
                    # read serialized version of exception thrown on server side
                    # useful only for java clients
                    serialized_exception = self._decode_field(FIELD_STRING)
                    # trash
                    del serialized_exception

            raise PyOrientCommandException(
                exception_class.decode('utf8'),
                [exception_message.decode('utf8')]
            )

        elif self._header[0] == 3:
            # Push notification, Node cluster changed
            # TODO: UNTESTED CODE!!!
            # FIELD_BYTE (OChannelBinaryProtocol.PUSH_DATA);  # WRITE 3
            # FIELD_INT (Integer.MIN_VALUE);  # SESSION ID = 2^-31
            # 80: \x50 Request Push 1 byte: Push command id
            push_command_id = self._decode_field(FIELD_BYTE)
            push_message = self._decode_field(FIELD_STRING)
            _, payload = self.get_serializer().decode(push_message)
            if self._push_callback:
                self._push_callback(push_command_id, payload)

            end_flag = self._decode_field(FIELD_BYTE)

            # this flag can be set more than once
            while end_flag == 3:
                self._decode_field(FIELD_INT)  # FAKE SESSION ID = 2^-31
                op_code = self._decode_field(FIELD_BYTE)  # 80: 0x50 Request Push

                # REQUEST_PUSH_RECORD	        79
                # REQUEST_PUSH_DISTRIB_CONFIG	80
                # REQUEST_PUSH_LIVE_QUERY	    81
                if op_code == 80:
                    # for node in
                    payload = self.get_serializer().decode(
                        self._decode_field(FIELD_STRING)
                    )  # JSON WITH THE NEW CLUSTER CFG

                    # reset the nodelist
                    self._node_list = []
                    for node in payload['members']:
                        self._node_list.append(OrientNode(node))

                end_flag = self._decode_field(FIELD_BYTE)

            # Try to set the new session id???
            self._header[1] = self._decode_field(FIELD_INT)  # REAL SESSION ID
            pass

    def _decode_body(self):
        # read body
        for field in self._fields_definition:
            self._body.append(self._decode_field(field))

        # clear field stack
        self._reset_fields_definition()
        return self

    def _decode_all(self):
        self._decode_header()
        self._decode_body()

    def fetch_response(self, *_continue):
        """
        # Decode header and body
        # If flag continue is set( Header already read ) read only body
        :param _continue:
        :return:
        """
        if len(_continue) != 0:
            self._body = []
            self._decode_body()
            self.dump_streams()
        # already fetched, get last results as cache info

        elif len(self._body) == 0:
            self._decode_all()
            self.dump_streams()

        return self._body

    def dump_streams(self):
        if is_debug_active():
            if len(self._output_buffer):
                print("\nRequest :")
                hexdump(self._output_buffer)

            if len(self._input_buffer):
                print("\nResponse:")
                hexdump(self._input_buffer)

    def _append(self, field):
        """
        @:rtype self: BaseMessage
        @type field: object
        """
        self._fields_definition.append(field)
        return self

    def __str__(self):

        return "\n_output_buffer: \n" + hexdump(self._output_buffer, 'return') \
               + "\n\n_input_buffer: \n" + hexdump(self._input_buffer, 'return')

    def send(self):
        if self._orientSocket.in_transaction is False:
            self._orientSocket.write(self._output_buffer)
            self._reset_fields_definition()

        if is_debug_active():
            self.dump_streams()
            # reset output buffer
            self._output_buffer = b""

        return self

    def close(self):
        self._orientSocket.close()

    @staticmethod
    def _encode_field(field):

        # tuple with type
        t, v = field
        _content = None

        if t['type'] == INT:
            _content = struct.pack("!i", v)

        elif t['type'] == SHORT:
            _content = struct.pack("!h", v)

        elif t['type'] == LONG:
            _content = struct.pack("!q", v)

        elif t['type'] == BOOLEAN:
            if sys.version_info[0] < 3:
                _content = chr(1) if v else chr(0)
            else:
                _content = bytes([1]) if v else bytes([0])

        elif t['type'] == BYTE:
            if sys.version_info[0] < 3:
                _content = v
            else:
                _content = bytes([ord(v)])

        elif t['type'] == BYTES:
            _content = struct.pack("!i", len(v)) + v

        elif t['type'] == STRING:

            if isinstance(v, str):
                v = v.encode('utf-8')

            _content = struct.pack("!i", len(v)) + v

        elif t['type'] == STRINGS:
            _content = b''
            for s in v:
                if sys.version_info[0] >= 3:
                    if isinstance(s, str):
                        s = s.encode('utf-8')
                else:
                    if isinstance(s, str):
                        s = s.encode('utf-8')
                _content += struct.pack("!i", len(s)) + s

        return _content

    def _decode_field(self, _type):
        """Decodes the part of the response as designated by "_type"."""
        _value = b""
        field_type = _type["type"]
        # read buffer length and decode value by field definition
        if _type['bytes'] is not None:
            _value = self._orientSocket.read(_type['bytes'])

        # if it is a string decode first 4 Bytes as INT
        # and try to read the buffer
        if field_type == STRING or field_type == BYTES:

            _len = struct.unpack('!i', _value)[0]
            if _len == -1 or _len == 0:
                _decoded_string = b''

            else:
                _decoded_string = self._orientSocket.read(_len)

            self._input_buffer += _value
            self._input_buffer += _decoded_string

            return _decoded_string

        elif field_type == RECORD:

            # record_type
            record_type = self._decode_field(_type['struct'][0])

            rid = "#" + str(self._decode_field(_type['struct'][1]))
            rid += ":" + str(self._decode_field(_type['struct'][2]))

            version = self._decode_field(_type['struct'][3])
            content = self._decode_field(_type['struct'][4])
            return {'rid': rid, 'record_type': record_type, 'content': content, 'version': version}

        elif field_type == LINK:

            rid = "#" + str(self._decode_field(_type['struct'][0]))
            rid += ":" + str(self._decode_field(_type['struct'][1]))
            return rid

        else:
            self._input_buffer += _value

            if field_type == BOOLEAN:
                return bool(ord(_value))

            elif field_type == BYTE:
                return ord(_value)

            elif field_type == CHAR:
                return _value

            elif field_type == SHORT:
                return struct.unpack('!h', _value)[0]

            elif field_type == INT:
                return struct.unpack('!i', _value)[0]

            elif field_type == LONG:
                return struct.unpack('!q', _value)[0]

    def _read_async_records(self):
        """
        # async-result-type byte as trailing byte of a record can be:
        # 0: no records remain to be fetched
        # 1: a record is returned as a result set
        # 2: a record is returned as pre-fetched to be loaded in client's
        #       cache only. It's not part of the result set but the client
        #       knows that it's available for later access
        """
        _status = self._decode_field(FIELD_BYTE)  # status

        while _status != 0:

            try:

                # if a callback for the cache is not set, raise exception
                if not hasattr(self._callback, '__call__'):
                    raise AttributeError()

                _record = self._read_record()

                if _status == 1:  # async record type
                    # async_records.append( _record )  # save in async
                    self._callback(_record)  # save in async
                elif _status == 2:  # cache
                    # cached_records.append( _record )  # save in cache
                    self._callback(_record)  # save in cache

            except AttributeError:
                # AttributeError: 'RecordLoadMessage' object has
                # no attribute '_command_type'
                raise PyOrientBadMethodCallException(
                    str(self._callback) + " is not a callable function", [])
            finally:
                # read new status and flush the debug buffer
                _status = self._decode_field(FIELD_BYTE)  # status

    def _read_record(self):
        """
        # The format depends if a RID is passed or an entire
            record with its content.

        # In case of null record then -2 as short is passed.

        # In case of RID -3 is passes as short and then the RID:
            (-3:short)(cluster-id:short)(cluster-position:long).

        # In case of record:
            (0:short)(record-type:byte)(cluster-id:short)
            (cluster-position:long)(record-version:int)(record-content:bytes)

        :raise: PyOrientNullRecordException
        :return: OrientRecordLink,OrientRecord
        """
        marker = self._decode_field(FIELD_SHORT)  # marker

        if marker == -2:
            raise PyOrientNullRecordException('NULL Record', [])
        elif marker == -3:
            res = OrientRecordLink(self._decode_field(FIELD_TYPE_LINK))
        else:
            # read record
            __res = self._decode_field(FIELD_RECORD)

            if self._orientSocket.serialization_type == OrientSerialization.Binary:
                class_name, data = self.get_serializer().decode(__res['content'])
            else:
                # bug in orientdb csv serialization in snapshot 2.0
                class_name, data = self.get_serializer().decode(__res['content'].rstrip())

            res = OrientRecord(
                dict(
                    __o_storage=data,
                    __o_class=data.pop('class', class_name),
                    __version=__res['version'],
                    __rid= get_hash(data.pop('rid')) if 'rid' in data else __res['rid']
                )
            )

        self._input_buffer = b''

        return res


class DbOpenMessage(BaseMessage):
    def __init__(self, _orient_socket):
        super(DbOpenMessage, self).__init__(_orient_socket)

        self._user = ''
        self._pass = ''
        self._client_id = ''
        self._db_name = ''
        self._db_type = DB_TYPE_DOCUMENT
        self._append((FIELD_BYTE, DB_OPEN_OP))
        self._need_token = False

    def prepare(self, params=None):

        if isinstance(params, tuple) or isinstance(params, list):
            try:
                self._db_name = params[0]
                self._user = params[1]
                self._pass = params[2]
                self.set_db_type(params[3])
                self._client_id = params[4]

            except IndexError:
                # Use default for non existent indexes
                pass

        self._append((FIELD_STRINGS, [NAME, VERSION]))
        self._append((FIELD_SHORT, SUPPORTED_PROTOCOL))
        self._append((FIELD_STRING, self._client_id))

        if self.get_protocol() > 21:
            self._append((FIELD_STRING, self._orientSocket.serialization_type))
            if self.get_protocol() > 26:
                self._append((FIELD_BOOLEAN, self._request_token))
                if self.get_protocol() >= 36:
                    self._append((FIELD_BOOLEAN, True))  # support-push
                    self._append((FIELD_BOOLEAN, True))  # collect-stats

        self._append((FIELD_STRING, self._db_name))

        if self.get_protocol() < 33:
            self._append((FIELD_STRING, self._db_type))

        self._append((FIELD_STRING, self._user))
        self._append((FIELD_STRING, self._pass))

        return super(DbOpenMessage, self).prepare()

    def fetch_response(self):
        self._append(FIELD_INT)  # session_id
        if self.get_protocol() > 26:
            self._append(FIELD_STRING)  # token # if FALSE: Placeholder

        self._append(FIELD_SHORT)  # cluster_num

        result = super(DbOpenMessage, self).fetch_response()
        if self.get_protocol() > 26:
            self._session_id, self._auth_token, cluster_num = result
            if self._auth_token == b'':
                self.set_session_token(False)
            self._update_socket_token()
        else:
            self._session_id, cluster_num = result

        # IMPORTANT needed to pass the id to other messages
        self._update_socket_id()

        clusters = []

        # Parsing cluster map TODO: this must be put in serialization interface
        for x in range(0, cluster_num):
            if self.get_protocol() < 24:
                cluster = OrientCluster(
                    self._decode_field(FIELD_STRING),
                    self._decode_field(FIELD_SHORT),
                    self._decode_field(FIELD_STRING),
                    self._decode_field(FIELD_SHORT)
                )
            else:
                cluster = OrientCluster(
                    self._decode_field(FIELD_STRING),
                    self._decode_field(FIELD_SHORT)
                )
            clusters.append(cluster)

        self._append(FIELD_STRING)  # orient node list | string ""
        self._append(FIELD_STRING)  # Orient release

        nodes_config, release = super(DbOpenMessage, self).fetch_response(True)

        # parsing server release version
        info = OrientVersion(release)

        nodes = []

        # parsing Node List TODO: this must be put in serialization interface
        if len(nodes_config) > 0:
            _, decoded = self.get_serializer().decode(nodes_config)
            self._node_list = []
            for node_dict in decoded['members']:
                self._node_list.append(OrientNode(node_dict))

        # set database opened
        self._orientSocket.db_opened = self._db_name

        return info, clusters, self._node_list
        # self._cluster_map = self._orientSocket.cluster_map = \
        #     Information([clusters, response, self._orientSocket])

        # return self._cluster_map

    def set_db_name(self, db_name):
        self._db_name = db_name
        return self

    def set_db_type(self, db_type):
        if db_type in DB_TYPES:
            # user choice storage if present
            self._db_type = db_type
        else:
            raise PyOrientBadMethodCallException(
                db_type + ' is not a valid database type', []
            )
        return self

    def set_client_id(self, _cid):
        self._client_id = _cid
        return self

    def set_user(self, _user):
        self._user = _user
        return self

    def set_pass(self, _pass):
        self._pass = _pass
        return self


#
# DB CLOSE
#
# Closes the database and the network connection to the OrientDB Server
# instance. No return is expected. The socket is also closed.
#
# Request: empty
#  Response: no response, the socket is just closed at server side
#
class DbCloseMessage(BaseMessage):
    def __init__(self, _orient_socket):
        super(DbCloseMessage, self).__init__(_orient_socket)

        # order matters
        self._append((FIELD_BYTE, DB_CLOSE_OP))

    @need_connected
    def prepare(self, params=None):
        return super(DbCloseMessage, self).prepare()

    def fetch_response(self):
        # set database closed
        self._orientSocket.db_opened = None
        super(DbCloseMessage, self).close()
        return 0


#
# DB EXISTS
#
# Asks if a database exists in the OrientDB Server instance. It returns true (non-zero) or false (zero).
#
# Request: (database-name:string) <-- before 1.0rc1 this was empty (server-storage-type:string - since 1.5-snapshot)
# Response: (result:byte)
#
# server-storage-type can be one of the supported types:
#  plocal as a persistent database
#  memory, as a volatile database
#
class DbExistsMessage(BaseMessage):
    def __init__(self, _orient_socket):
        super(DbExistsMessage, self).__init__(_orient_socket)

        self._db_name = ''
        self._storage_type = ''

        if self.get_protocol() > 16:  # 1.5-SNAPSHOT
            self._storage_type = STORAGE_TYPE_PLOCAL
        else:
            self._storage_type = STORAGE_TYPE_LOCAL

        # order matters
        self._append((FIELD_BYTE, DB_EXIST_OP))

    @need_connected
    def prepare(self, params=None):

        if isinstance(params, tuple) or isinstance(params, list):
            try:
                self._db_name = params[0]
                # user choice storage if present
                self.set_storage_type(params[1])

            except IndexError:
                # Use default for non existent indexes
                pass

        if self.get_protocol() >= 6:
            self._append((FIELD_STRING, self._db_name))  # db_name

        if self.get_protocol() >= 16:
            # > 16 1.5-snapshot
            # custom choice server_storage_type
            self._append((FIELD_STRING, self._storage_type))

        return super(DbExistsMessage, self).prepare()

    def fetch_response(self):
        self._append(FIELD_BOOLEAN)
        return super(DbExistsMessage, self).fetch_response()[0]

    def set_db_name(self, db_name):
        self._db_name = db_name
        return self

    def set_storage_type(self, storage_type):
        if storage_type in STORAGE_TYPES:
            # user choice storage if present
            self._storage_type = storage_type
        else:
            raise PyOrientBadMethodCallException(
                storage_type + ' is not a valid storage type', []
            )
        return self


#
# DB CREATE
#
# Creates a database in the remote OrientDB server instance
#
# Request: (database-name:string)(database-type:string)(storage-type:string)
# Response: empty
#
# - database-name as string. Example: "demo"
# - database-type as string, can be 'document' or 'graph' (since version 8). Example: "document"
# - storage-type can be one of the supported types:
# - plocal, as a persistent database
# - memory, as a volatile database
#
class DbCreateMessage(BaseMessage):
    def __init__(self, _orient_socket):
        super(DbCreateMessage, self).__init__(_orient_socket)

        self._db_name = ''
        self._db_type = DB_TYPE_DOCUMENT
        self._storage_type = ''
        self._backup_path = -1

        if self.get_protocol() > 16:  # 1.5-SNAPSHOT
            self._storage_type = STORAGE_TYPE_PLOCAL
        else:
            self._storage_type = STORAGE_TYPE_LOCAL

        # order matters
        self._append((FIELD_BYTE, DB_CREATE_OP))

    @need_connected
    def prepare(self, params=None):

        if isinstance(params, tuple) or isinstance(params, list):
            try:
                self._db_name = params[0]
                self.set_db_type(params[1])
                self.set_storage_type(params[2])
                self.set_backup_path(params[3])
            except IndexError:
                pass

        self._append(
            (FIELD_STRINGS, [self._db_name, self._db_type, self._storage_type])
        )

        if self.get_protocol() > 35:
            if isinstance(self._backup_path, int):
                field_type = FIELD_INT
            else:
                field_type = FIELD_STRING
            self._append((field_type, self._backup_path))

        return super(DbCreateMessage, self).prepare()

    def fetch_response(self):
        super(DbCreateMessage, self).fetch_response()
        # set database opened
        self._orientSocket.db_opened = self._db_name
        return

    def set_db_name(self, db_name):
        self._db_name = db_name
        return self

    def set_backup_path(self, backup_path):
        self._backup_path = backup_path
        return self

    def set_db_type(self, db_type):
        if db_type in DB_TYPES:
            # user choice storage if present
            self._db_type = db_type
        else:
            raise PyOrientBadMethodCallException(
                db_type + ' is not a valid database type', []
            )
        return self

    def set_storage_type(self, storage_type):
        if storage_type in STORAGE_TYPES:
            # user choice storage if present
            self._storage_type = storage_type
        else:
            raise PyOrientBadMethodCallException(
                storage_type + ' is not a valid storage type', []
            )
        return self


#
# DB DROP
#
# Removes a database from the OrientDB Server instance.
# It returns nothing if the database has been deleted or throws
# a OStorageException if the database doesn't exists.
#
# Request: (database-name:string)(server-storage-type:string - since 1.5-snapshot)
#  Response: empty
#
# - server-storage-type can be one of the supported types:
# - plocal as a persistent database
# - memory, as a volatile database
#
class DbDropMessage(BaseMessage):
    def __init__(self, _orient_socket):
        super(DbDropMessage, self). \
            __init__(_orient_socket)

        self._db_name = ''
        self._storage_type = ''

        if self.get_protocol() > 16:  # 1.5-SNAPSHOT
            self._storage_type = STORAGE_TYPE_PLOCAL
        else:
            self._storage_type = STORAGE_TYPE_LOCAL

        # order matters
        self._append((FIELD_BYTE, DB_DROP_OP))

    @need_connected
    def prepare(self, params=None):

        if isinstance(params, tuple) or isinstance(params, list):
            try:
                self._db_name = params[0]
                self.set_storage_type(params[1])
            except IndexError:
                # Use default for non existent indexes
                pass

        self._append((FIELD_STRING, self._db_name))  # db_name

        if self.get_protocol() >= 16:  # > 16 1.5-snapshot
            # custom choice server_storage_type
            self._append((FIELD_STRING, self._storage_type))

        return super(DbDropMessage, self).prepare()

    def fetch_response(self):
        return super(DbDropMessage, self).fetch_response()

    def set_db_name(self, db_name):
        self._db_name = db_name
        return self

    def set_storage_type(self, storage_type):
        if storage_type in STORAGE_TYPES:
            # user choice storage if present
            self._storage_type = storage_type
        else:
            raise PyOrientBadMethodCallException(
                storage_type + ' is not a valid storage type', []
            )
        return self


#
# DB COUNT RECORDS
#
# Asks for the number of records in a database in
# the OrientDB Server instance.
#
# Request: empty
# Response: (count:long)
#
class DbCountRecordsMessage(BaseMessage):
    def __init__(self, _orient_socket):
        super(DbCountRecordsMessage, self).__init__(_orient_socket)

        self._user = ''
        self._pass = ''

        # order matters
        self._append((FIELD_BYTE, DB_COUNT_RECORDS_OP))

    @need_db_opened
    def prepare(self, params=None):
        return super(DbCountRecordsMessage, self).prepare()

    def fetch_response(self):
        self._append(FIELD_LONG)
        return super(DbCountRecordsMessage, self).fetch_response()[0]


#
# DB RELOAD
#
# Reloads database information. Available since 1.0rc4.
#  
#  Request: empty
#  Response:(num-of-clusters:short)[(cluster-name:string)(cluster-id:short)]
#
class DbReloadMessage(BaseMessage):
    def __init__(self, _orient_socket):
        super(DbReloadMessage, self).__init__(_orient_socket)

        # order matters
        self._append((FIELD_BYTE, DB_RELOAD_OP))

    @need_connected
    def prepare(self, params=None):
        return super(DbReloadMessage, self).prepare()

    def fetch_response(self):

        self._append(FIELD_SHORT)  # cluster_num

        cluster_num = super(DbReloadMessage, self).fetch_response()[0]

        clusters = []

        # Parsing cluster map
        for x in range(0, cluster_num):
            if self.get_protocol() < 24:
                cluster = OrientCluster(
                    self._decode_field(FIELD_STRING),
                    self._decode_field(FIELD_SHORT),
                    self._decode_field(FIELD_STRING),
                    self._decode_field(FIELD_SHORT)
                )
            else:
                cluster = OrientCluster(
                    self._decode_field(FIELD_STRING),
                    self._decode_field(FIELD_SHORT)
                )
            clusters.append(cluster)

        return clusters


#
# DB SIZE
#
# Asks for the size of a database in the OrientDB Server instance.
#
# Request: empty
# Response: (size:long)
#
class DbSizeMessage(BaseMessage):
    def __init__(self, _orient_socket):
        super(DbSizeMessage, self).__init__(_orient_socket)

        # order matters
        self._append((FIELD_BYTE, DB_SIZE_OP))

    @need_db_opened
    def prepare(self, params=None):
        return super(DbSizeMessage, self).prepare()

    def fetch_response(self):
        self._append(FIELD_LONG)
        return super(DbSizeMessage, self).fetch_response()[0]


#
# DB List
#
# Asks for the size of a database in the OrientDB Server instance.
#
# Request: empty
# Response: (size:long)
#
class DbListMessage(BaseMessage):
    def __init__(self, _orient_socket):
        super(DbListMessage, self).__init__(_orient_socket)

        # order matters
        self._append((FIELD_BYTE, DB_LIST_OP))

    @need_connected
    def prepare(self, params=None):
        return super(DbListMessage, self).prepare()

    def fetch_response(self):
        self._append(FIELD_BYTES)
        __record = super(DbListMessage, self).fetch_response()[0]
        # bug in orientdb csv serialization in snapshot 2.0,
        # strip trailing spaces
        _, data = self.get_serializer().decode(__record.rstrip())

        return OrientRecord(dict(__o_storage=data))


class ConnectMessage(BaseMessage):

    def __init__(self, _orient_socket):
        super(ConnectMessage, self).__init__(_orient_socket)

        self._user = ''
        self._pass = ''
        self._client_id = ''
        self._need_token = False
        self._append((FIELD_BYTE, CONNECT_OP))

    def prepare(self, params=None):

        if isinstance(params, tuple) or isinstance(params, list):
            try:
                self._user = params[0]
                self._pass = params[1]
                self._client_id = params[2]

            except IndexError:
                # Use default for non existent indexes
                pass

        self._append((FIELD_STRINGS, [NAME, VERSION]))
        self._append((FIELD_SHORT, SUPPORTED_PROTOCOL))

        self._append((FIELD_STRING, self._client_id))

        if self.get_protocol() > 21:
            self._append((FIELD_STRING, self._orientSocket.serialization_type))
            if self.get_protocol() > 26:
                self._append((FIELD_BOOLEAN, self._request_token))
                if self.get_protocol() > 32:
                    self._append((FIELD_BOOLEAN, True))  # support-push v34
                    self._append((FIELD_BOOLEAN, True))  # collect-stats v34

        self._append((FIELD_STRING, self._user))
        self._append((FIELD_STRING, self._pass))

        return super(ConnectMessage, self).prepare()

    def fetch_response(self):
        self._append(FIELD_INT)
        if self.get_protocol() > 26:
            self._append(FIELD_STRING)

        result = super(ConnectMessage, self).fetch_response()

        # IMPORTANT needed to pass the id to other messages
        self._session_id = result[0]
        self._update_socket_id()

        if self.get_protocol() > 26:
            if result[1] is None:
                self.set_session_token(False)
            self._auth_token = result[1]
            self._update_socket_token()

        return self._session_id

    def set_user(self, _user):
        self._user = _user
        return self

    def set_pass(self, _pass):
        self._pass = _pass
        return self

    def set_client_id(self, _cid):
        self._client_id = _cid
        return self