
alice = Agent("I'M 5UppER Kewl h4zKEr")
bob = Agent()
mallory = MITM()

# Alice has da message, Bob doesn't
assert alice.msg
assert not bob.msg

# Negotiate parameters publicly
mallory.receive_public_data(*alice.send_public_data())
bob.receive_public_data(*mallory.send_public_data())
mallory.receive_public_data(*bob.send_public_data())
alice.receive_public_data(*mallory.send_public_data())

# Exchange keys publicly
mallory.receive_public_key(alice.send_public_key())
bob.receive_public_key(mallory.send_public_key())
mallory.receive_public_key(bob.send_public_key())
alice.receive_public_key(mallory.send_public_key())

# Pass da message
bob.receive_message(mallory.intercept_message(alice.send_message()))
# Bob has it now
assert bob.msg == alice.msg
# Mallory too
assert mallory.msg == alice.msg
