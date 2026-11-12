def test_invalid_student_id(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.get("/students/asd/profile")

    assert response.status_code == 400

def test_non_existent_student_id(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.get("/students/11/profile")

    assert response.status_code == 404
