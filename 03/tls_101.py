alice = Agent("I'M 5UppER Kewl h4zKEr")
bob = Agent()


# Alice has da message, Bob doesn't
assert alice.msg
assert not bob.msg

# Negotiate parameters publicly
bob.receive_public_data(*alice.send_public_data())
alice.receive_public_data(*bob.send_public_data())

# Exchange keys publicly
bob.receive_public_key(alice.send_public_key())
alice.receive_public_key(bob.send_public_key())

# Pass da message
bob.receive_message(alice.send_message())
# Bob has it now
assert alice.msg == bob.msg
