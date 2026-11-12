def test_student_can_see_own_profile(client, utils):
    utils.login(client, "alice", "alicepw")

    response = client.get("/students/1001/profile")

    assert response.status_code == 200

def test_admin_can_see_student_profile(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.get("/students/1001/profile")

    assert response.status_code == 200

def test_student_cannot_see_other_student_profile(client, utils):
    utils.login(client, "bob", "bobpw")

    response = client.get("/students/1001/profile")

    assert response.status_code == 403

def test_professor_cannot_see_student_profile(client, utils):
    utils.login(client, "prof_srs", "profpw")

    response = client.get("/student/1001/profile")

    assert response.status_code == 403

def test_unauthenticated_cannot_see_student_profile(client):
    response = client.get("/student/1001/profile")

    assert response.status_code == 401
