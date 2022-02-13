from os import environ

import pytest
from pydg import PydgClientException, create_client


@pytest.fixture(scope="class")
def dsn():
    return environ["EDGEDB_DSN"]


@pytest.fixture
def con(request, dsn):
    conn = create_client(dsn)

    def fin():
        try:
            conn.close()
        except PydgClientException:
            pass

    request.addfinalizer(fin)
    return conn
