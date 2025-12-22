from app import app


def test_index_route():
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert b"Enter Base API URL" in response.data
