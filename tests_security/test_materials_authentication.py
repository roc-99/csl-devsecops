def test_student_can_read_materials(client, utils):
    utils.login(client, "alice", "alicepw")

    response = client.get("/files?path=secure-coding.txt")

    assert response.status_code == 200

def test_unautherized_cannot_read_materials(client, utils):
    response = client.get("/files?path=secure-coding.txt")

    assert response.status_code == 401
