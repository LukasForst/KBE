
message = b'Trust no one'
msg_sha1 = generate_message_hash(message)
private_key, public_key = generate_key(p, q, e=3)
signature = generate_signature(private_key, msg_sha1)
assert verify_signature(public_key, signature, msg_sha1)
assert verify_signature(public_key, fake_signature(msg_sha1), msg_sha1)
