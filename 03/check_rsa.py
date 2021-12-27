
private_key, public_key = generate_key(e=3)
message = "I will not write crypto code myself, but defer to high-level libraries written by experts who took the right decisions for me".encode()
assert message == decrypt(private_key, encrypt(public_key, message))
