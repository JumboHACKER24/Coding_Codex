from modules.password import hash_password, verify_password


def test_hash_and_verify():
    pwd = "S3cureP@ssw0rd!"
    hashed = hash_password(pwd)
    assert isinstance(hashed, str)
    assert verify_password(pwd, hashed) == "Password is correct. Access granted."
    assert verify_password("wrongpw", hashed) == "Password is incorrect. Access denied."
