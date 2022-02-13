from urllib.parse import urlparse

from pydg.core import Connection, PydgClientException
from . import _version

EDGEDB_SCHEME = "edgedb"


def _parse_dsn(dsn):
    url = urlparse(dsn, scheme=EDGEDB_SCHEME)
    if url.scheme != EDGEDB_SCHEME:
        raise PydgClientException(f"The DSN scheme must be {EDGEDB_SCHEME}")

    path = url.path

    params = {
        "port": url.port,
        "host": url.hostname,
        "user": url.username,
        "password": url.password,
        "database": None if path == "" else path[1:],
    }

    return {k: v for k, v in params.items() if v is not None}


def create_client(dsn):
    return Connection(**_parse_dsn(dsn))


__all__ = [
    "connect",
]


__version__ = _version.get_versions()["version"]
