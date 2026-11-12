import baseline_secure_coding_api as api

def test_professor_can_change_grade(client, utils):
    utils.login(client, "prof_srs", "profpw")

    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 18},
    )

    assert response.status_code == 200
    assert api.find_grade(1001, "SRS")["grade"] == 18

def test_invalid_student_id(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.post(
            "/grades/update",
            json={"student_id": "asd", "course_id": "SRS", "grade": 18}
        )

    assert response.status_code == 400

def test_non_existing_student_id(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.post(
            "/grades/update",
            json={"student_id": 11, "course_id": "SRS", "grade": 18}
        )

    assert response.status_code == 400

def test_invalid_course_id(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.post(
            "/grades/update",
            json={"student_id": 1001, "course_id": "asd", "grade": 18}
        )

    assert response.status_code == 400

def test_invalid_grade(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.post(
            "/grades/update",
            json={"student_id": 1001, "course_id": "SRS", "grade": "A+"}
        )

    assert response.status_code == 400

def test_out_of_range_grade_1(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.post(
            "/grades/update",
            json={"student_id": 1001, "course_id": "SRS", "grade": -1}
        )

    assert response.status_code == 400

def test_out_of_range_grade_2(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.post(
            "/grades/update",
            json={"student_id": 1001, "course_id": "SRS", "grade": 21}
        )

    assert response.status_code == 400

def test_empty_json_request(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.post(
            "/grades/update",
            json={}
        )

    assert response.status_code == 400
