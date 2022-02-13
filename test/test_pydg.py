from pydg import create_client


def test_con():
    create_client("edgedb://localhost:10700/tlocke")
