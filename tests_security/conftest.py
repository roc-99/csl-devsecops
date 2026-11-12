import copy
import pytest
import baseline_secure_coding_api as api

@pytest.fixture(autouse=True)
def restore_grades():
    original = copy.deepcopy(api.GRADES)
    yield
    api.GRADES[:] = original

@pytest.fixture
def client():
    with api.app.test_client() as client:
        yield client

class Utils:
    @staticmethod
    def login(client, username, password):
        response = client.post(
            "/login",
            data={"username": username, "password": password},
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert response.get_json()["user"] == username




@pytest.fixture
def utils():
    return Utils
