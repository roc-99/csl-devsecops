import baseline_secure_coding_api as api

#----------------- Grade update -------------------
def test_assigned_professor_can_update_grade(client, utils):
    utils.login(client, "prof_srs", "profpw")
    
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 18},
    )

    assert response.status_code == 200
    assert api.find_grade(1001, "SRS")["grade"] == 18

def test_admin_can_update_grade(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 18},
    )

    assert response.status_code == 200
    assert api.find_grade(1001, "SRS")["grade"] == 18

def test_unassigned_professor_cannot_update_grade(client, utils):
    utils.login(client, "prof_srs", "profpw")
    
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SSD", "grade": 18},
    )

    assert response.status_code == 403
    assert api.find_grade(1001, "SSD")["grade"] == 16

def test_student_cannot_update_grade(client, utils):
    utils.login(client, "alice", "alicepw")
    
    response = client.post(
            "/grades/update",
            json= {
                    "student_id": 1001,
                    "course_id": "SRS",
                    "grade": 18,
                }
            )

    assert response.status_code == 403
    assert api.find_grade(1001, "SRS")["grade"] == 14

def test_unauthencated_cannot_update_grade(client):
    response = client.post(
            "/grades/update",
            json= {
                    "student_id": 1001,
                    "course_id": "SRS",
                    "grade": 18,
                }
            )
    
    assert response.status_code == 401
    assert api.find_grade(1001, "SRS")["grade"] == 14

#---------------------- Grade read --------------------
def test_assigned_professor_can_see_student_grades(client, utils):
    utils.login(client, "prof_srs", "profpw")

    response = client.get("/grades/1001")

    assert response.status_code == 200

    for grade in response.json:
        assert grade["course_id"] == "SRS"

def test_student_can_see_own_grades(client, utils):
    utils.login(client, "alice", "alicepw")

    response = client.get("/grades/1001")

    assert response.status_code == 200

    for grade in response.json:
        assert grade["student_id"] == 1001

def test_admin_can_see_student_grades(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.get("/grades/1001")

    assert response.status_code == 200
    assert len(response.json) == 2

def test_student_cannot_see_other_student_grades(client, utils):
    utils.login(client, "bob", "bobpw")

    response = client.get("/grades/1001")

    assert response.status_code == 403
    # Maybe add check to see if response still came

def test_unauthenticated_cannot_see_student_grades(client):
    response = client.get("/grades/1001")

    assert response.status_code == 401
