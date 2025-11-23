from modules.encryption import aes_ed, rsa_ed


def test_aes_roundtrip():
    key_hex, cipher_hex, plain = aes_ed(b"hello world")
    assert plain == "hello world"
    # 32 bytes -> 64 hex chars
    assert len(key_hex) == 64
    assert len(cipher_hex) > 0


def test_rsa_roundtrip():
    cipher_hex, plain = rsa_ed("hello rsa")
    assert plain == "hello rsa"
    assert len(cipher_hex) > 0
