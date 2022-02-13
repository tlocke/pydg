import socket
import struct

import scramp

from pydg.converters import (
    pack_bytes,
    pack_int32,
    pack_string,
    pack_uint16,
    pack_uint8,
    unpack_bytes,
    unpack_data_element,
    unpack_header,
    unpack_multi,
    unpack_string,
    unpack_uint16,
    unpack_uint32,
    unpack_uint8,
    unpack_uint8_int32,
    unpack_uuid,
)

from pydg.error_codes import ERROR_CODES


class PydgException(Exception):
    pass


class PydgClientException(PydgException):
    """Generic exception raised for errors that are related to the database
    interface rather than the database itself.
    """

    pass


class PydgServerException(PydgException):
    """Generic exception raised for errors that are related to the database."""

    pass


# Server message codes
AUTHENTICATION = b"R"
COMMAND_COMPLETE = b"C"
COMMAND_DATA_DESCRIPTION = b"T"
DATA = b"D"
DUMP_HEADER = b"@"
DUMP_BLOCK = b"="
ERROR_RESPONSE = b"E"
LOG_MESSAGE = b"L"
PARAMETER_STATUS = b"S"
PREPARE_COMPLETE = b"1"
READY_FOR_COMMAND = b"Z"
RESTORE_READY = b"+"
SERVER_HANDSHAKE = b"v"
SERVER_KEY_DATA = b"K"

# Client message codes
AUTHENTICATION_SASL_INITIAL_RESPONSE = b"p"
AUTHENTICATION_SASL_RESPONSE = b"r"
CLIENT_HANDSHAKE = b"V"
DESCRIBE_STATEMENT = b"D"
DUMP = b">"
EXECUTE = b"E"
EXECUTE_SCRIPT = b"Q"
FLUSH = b"H"
PREPARE = b"P"
OPTIMISTIC_EXECUTE = b"O"
RESTORE = b"<"
RESTORE_BLOCK = b"="
RESTORE_EOF = b"."
SYNC = b"S"
TERMINATE = b"X"

ERROR_SEVERITY = {
    b"\x78": "ERROR",
    b"\xc8": "FATAL",
    b"\xff": "PANIC",
}

MESSAGE_SEVERITY = {
    b"\x14": "DEBUG",
    b"\x28": "INFO",
    b"\x3c": "NOTICE",
    b"\x50": "WARNING",
}

CARDINALITY_NO_RESULT = b"\x6e"
CARDINALITY_AT_MOST_ONE = b"\x6f"
CARDINALITY_ONE = b"\x41"
CARDINALITY_MANY = b"\x6d"
CARDINALITY_AT_LEAST_ONE = b"\x4d"

IO_FORMAT_BINARY = b"\x62"
IO_FORMAT_JSON = b"\x6a"
IO_FORMAT_JSON_ELEMENTS = b"\x4a"

DESCRIBE_ASPECT_DATA_DESCRIPTION = b"\x54"


def _create_message(code, *data):
    d = b"".join(data)
    return code + pack_int32(len(d)) + d


FLUSH_MSG = _create_message(FLUSH)
RESTORE_EOF_MSG = _create_message(RESTORE_EOF)
SYNC_MSG = _create_message(SYNC)
TERMINATE_MSG = _create_message(TERMINATE)


class Connection:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __init__(
        self,
        user="edgedb",
        host="localhost",
        database="edgedb",
        port="5656",
        password=None,
        source_address=None,
        ssl_context=None,
        timeout=None,
        tcp_keepalive=True,
    ):

        self._caches = {}

        try:
            self._usock = socket.create_connection(
                (host, port), timeout, source_address
            )
        except socket.error as e:
            raise PydgClientException(
                f"Can't create a connection to host {host} and port {port} "
                f"(timeout is {timeout} and source_address is {source_address})."
            ) from e

        if tcp_keepalive:
            self._usock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        self.channel_binding = None
        if ssl_context is not None:
            try:
                import ssl

                if ssl_context is True:
                    ssl_context = ssl.create_default_context()

                self._usock = ssl_context.wrap_socket(self._usock, server_hostname=host)

                self.channel_binding = scramp.make_channel_binding(
                    "tls-server-end-point", self._usock
                )

            except ImportError:
                raise PydgClientException(
                    "SSL required but ssl module not available in this python "
                    "installation."
                )

        self._sock = self._usock.makefile(mode="rwb")

        def sock_flush():
            try:
                self._sock.flush()
            except OSError as e:
                raise PydgClientException("network error on flush") from e

        self._flush = sock_flush

        def sock_read(b):
            try:
                return self._sock.read(b)
            except OSError as e:
                raise PydgClientException("network error on read") from e

        self._read = sock_read

        def sock_write(d):
            try:
                self._sock.write(d)
            except OSError as e:
                raise PydgClientException("network error on write") from e

        self._write = sock_write
        self._backend_key_data = None

        self.edb_types = {}
        self.py_types = {}

        self.message_types = {
            AUTHENTICATION: self.handle_AUTHENTICATION,
            COMMAND_COMPLETE: self.handle_COMMAND_COMPLETE,
            COMMAND_DATA_DESCRIPTION: self.handle_COMMAND_DATA_DESCRIPTION,
            DATA: self.handle_DATA,
            DUMP_HEADER: self.handle_DUMP_HEADER,
            DUMP_BLOCK: self.handle_DUMP_BLOCK,
            ERROR_RESPONSE: self.handle_ERROR_RESPONSE,
            LOG_MESSAGE: self.handle_LOG_MESSAGE,
            PARAMETER_STATUS: self.handle_PARAMETER_STATUS,
            PREPARE_COMPLETE: self.handle_PREPARE_COMPLETE,
            READY_FOR_COMMAND: self.handle_READY_FOR_COMMAND,
            RESTORE_READY: self.handle_RESTORE_READY,
            SERVER_HANDSHAKE: self.handle_SERVER_HANDSHAKE,
            SERVER_KEY_DATA: self.handle_SERVER_KEY_DATA,
        }

        val = bytearray(pack_uint16(1))  # major_ver
        val.append(pack_uint16(0))  # minor_ver
        for k, v in (("user", user), ("database", database)):
            val.append(pack_string(k))
            val.append(pack_string(v))

        self._send_message(CLIENT_HANDSHAKE, val)
        self._flush()

        code = self.error = None
        while code not in (READY_FOR_COMMAND, ERROR_RESPONSE):
            code, data_len = unpack_uint8_int32(self._read(5))
            self.message_types[code](self._read(data_len), None)
        if self.error is not None:
            raise self.error

        self.in_transaction = False

    def register_out_adapter(self, typ, out_func):
        self.py_types[typ] = out_func

    def register_in_adapter(self, oid, in_func):
        self.pg_types[oid] = in_func

    def handle_AUTHENTICATION(self, data, context):
        """https://www.edgedb.com/docs/reference/protocol/messages"""

        auth_status, d = unpack_uint32(data)
        if auth_status == 0:
            pass

        elif auth_status == 10:
            # AuthenticationSASL
            num_methods, d = unpack_uint32(d)
            methods, d = unpack_multi(d, num_methods, unpack_string)

            self.auth = scramp.ScramClient(
                methods,
                self.user.decode("utf8"),
                self.password.decode("utf8"),
                channel_binding=self.channel_binding,
            )

            method = pack_string(self.auth.mechanism_name)
            sasl_data = pack_bytes(self.auth.get_client_first())

            self._send_message(AUTHENTICATION_SASL_INITIAL_RESPONSE, method, sasl_data)
            self._flush()

        elif auth_status == 11:
            # AuthenticationSASLContinue
            sasl_data, d = unpack_bytes(d)
            self.auth.set_server_first(sasl_data.decode("utf8"))

            # SASLResponse
            msg = pack_bytes(self.auth.get_client_final())
            self._send_message(AUTHENTICATION_SASL_RESPONSE, msg)
            self._flush()

        elif auth_status == 12:
            # AuthenticationSASLFinal
            self.auth.set_server_final(data[4:].decode("utf8"))

        else:
            raise PydgClientException(
                f"Authentication status {auth_status} not recognized by pydg."
            )

    def handle_COMMAND_COMPLETE(self, data, context):
        num_headers, d = unpack_uint16(data)
        headers, d = unpack_multi(d, num_headers, unpack_header)

        status, d = unpack_string(d)

        context.headers = headers
        context.status = status

    def handle_COMMAND_DATA_DESCRIPTION(self, data, context):
        num_headers, d = unpack_uint16(data)
        headers, d = unpack_multi(d, num_headers, unpack_header)
        result_cardinality, d = unpack_uint8(d)
        input_typedesc_id = unpack_uuid(d)
        input_typedesc = unpack_bytes(d)
        output_typedesc_id = unpack_uuid(d)
        output_typedesc = unpack_bytes(d)

        context.description_headers = headers
        context.result_cardinality = result_cardinality
        context.input_typedesc_id = input_typedesc_id
        context.input_typedesc = input_typedesc
        context.output_typedesc_id = output_typedesc_id
        context.output_typedesc = output_typedesc

    def handle_DATA(self, data, context):
        num_data, d = unpack_uint16(data)
        data, d = unpack_multi(d, num_data, unpack_data_element)
        context.data.extend(data)

    def handle_DUMP_HEADER(self, data, context):
        pass

    def handle_DUMP_BLOCK(self, data, context):
        pass

    def handle_ERROR_RESPONSE(self, data, context):
        msg = {}
        severity, d = unpack_uint8(data)
        msg["severity"] = ERROR_SEVERITY[severity]

        error_code, d = unpack_uint32(d)
        msg["error_code"] = ERROR_CODES[error_code]
        message, d = unpack_string(d)
        msg["message"] = message
        num_attributes, d = unpack_uint16(d)
        attributes, d = unpack_multi(d, num_attributes, unpack_header)
        msg["attributes"] = attributes

        self.error = PydgServerException(msg)

    def handle_LOG_MESSAGE(self, data, context):
        severity, d = unpack_uint8(data)
        code, d = unpack_uint32(d)
        text, d = unpack_string(d)
        num_attributes, d = unpack_uint16(d)
        attributes, d = unpack_multi(d, num_attributes, unpack_header)

        context.log.append(
            {
                "severity": MESSAGE_SEVERITY[severity],
                "code": ERROR_CODES[code],
                "text": text,
                "attributes": attributes,
            }
        )

    def handle_PARAMETER_STATUS(self, data, context):
        pass

    def handle_PREPARE_COMPLETE(self, data, context):
        num_headers, d = unpack_uint16(data)
        headers, d = unpack_multi(d, num_headers, unpack_header)
        result_cardinality, d = unpack_uint8(d)
        input_typedesc_id = unpack_uuid(d)
        input_typedesc = unpack_bytes(d)

        context.description_headers = headers
        context.result_cardinality = result_cardinality
        context.input_typedesc_id = input_typedesc_id
        context.input_typedesc = input_typedesc

    def handle_READY_FOR_COMMAND(self, data, context):
        num_headers, d = unpack_uint16(data)
        for header in unpack_multi(d, num_headers, unpack_header):
            raise PydgClientException(f"Unrecognized header {header}")
        transaction_state, d = unpack_uint8(d)
        self.transaction_state = transaction_state

    def handle_RESTORE_READY(self, data, context):
        pass

    def handle_SERVER_HANDSHAKE(self, data, context):
        pass

    def handle_SERVER_KEY_DATA(self, data, context):
        pass

    def handle_messages(self, context):
        code = self.error = None

        while code != READY_FOR_COMMAND:

            try:
                code, data_len = unpack_uint8_int32(self._read(5))
            except struct.error as e:
                raise PydgClientException("network error on read") from e

            self.message_types[code](self._read(data_len), context)

        if self.error is not None:
            raise self.error

    def close(self):
        """Closes the database connection."""
        try:
            self._write(TERMINATE_MSG)
            self._flush()
            self._sock.close()
        except AttributeError:
            raise PydgClientException("connection is closed")
        except ValueError:
            raise PydgClientException("connection is closed")
        except socket.error:
            pass
        finally:
            self._usock.close()
            self._sock = None

    def send_PREPARE(self, expected_cardinality, statement_name, command):
        num_headers = pack_uint16(0)
        io_format = pack_uint8(IO_FORMAT_BINARY)

        self._send_message(
            PREPARE,
            num_headers,
            io_format,
            expected_cardinality,
            pack_bytes(statement_name),
            pack_string(command),
        )
        self._write(FLUSH_MSG)

    def send_DESCRIBE_STATEMENT(self, statement_name):
        num_headers = pack_uint16(0)
        aspect = pack_uint8(DESCRIBE_ASPECT_DATA_DESCRIPTION)
        self._send_message(
            DESCRIBE_STATEMENT, num_headers, aspect, pack_bytes(statement_name)
        )
        self._write(FLUSH_MSG)

    def send_EXECUTE_SCRIPT(self, script):
        num_headers = pack_uint16(0)
        self._send_message(EXECUTE_SCRIPT, num_headers, pack_string(script))

    def execute_script(self, script):
        context = Context()

        self.send_EXECUTE_SCRIPT(script)
        self._flush()
        self.handle_messages(context)

        return context

    def execute(self, expected_cardinality, statement_name, command):
        context = Context()

        self.send_PREPARE(self, expected_cardinality, statement_name, command)
        self._flush()
        self.handle_messages(context)
        self.send_DESCRIBE_STATEMENT(statement_name)
        self.send_EXECUTE()

        self._write(SYNC_MSG)
        self._flush()
        self.handle_messages(context)

        return context

    def _send_message(self, code, *data):
        try:
            self._write(_create_message(code, *data))
        except ValueError as e:
            if str(e) == "write to closed file":
                raise PydgClientException("connection is closed")
            else:
                raise e
        except AttributeError:
            raise PydgClientException("connection is closed")

    def send_EXECUTE(self, statement_name):
        """https://www.edgedb.com/docs/reference/protocol/messages"""
        num_headers = pack_uint16(0)
        arguments = pack_bytes(b"")
        self._send_message(EXECUTE, num_headers, pack_bytes(statement_name), arguments)


class Context:
    def __init__(self, stream=None, columns=None, input_funcs=None):
        self.rows = None if columns is None else []
        self.row_count = -1
        self.columns = columns
        self.stream = stream
        self.input_funcs = [] if input_funcs is None else input_funcs
