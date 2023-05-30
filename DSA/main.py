from random import randrange
from hashlib import sha1
from gmpy2 import xmpz, to_binary, invert, powmod, is_prime

# Function to generate prime numbers p and q
def generate_p_q(key_length, security_parameter):
    # Compute the number of bits in q
    num_bits_q = security_parameter
    # Compute the number of blocks for p
    num_blocks_p = (key_length - 1) // num_bits_q
    remaining_bits_p = (key_length - 1) % num_bits_q

    while True:
        # Generate a random number s
        s = xmpz(randrange(1, 2 ** num_bits_q))
        # Compute the hash of s
        hash_s = sha1(to_binary(s)).hexdigest()
        # Compute zz
        zz = xmpz((s + 1) % (2 ** num_bits_q))
        # Compute the hash of zz
        hash_zz = sha1(to_binary(zz)).hexdigest()
        # Intermediate result U for computing q
        U = int(hash_s, 16) ^ int(hash_zz, 16)
        # Form a mask to obtain bits from security_parameter
        mask = 2 ** (security_parameter - 1) + 1
        # Compute q using U and the mask
        q = U | mask
        # Check if q is a prime number
        if is_prime(q, 20):
            break

    i = 0
    j = 2
    while i < 4096:
        V = []
        for k in range(num_blocks_p + 1):
            # Generate an argument for hashing
            arg = xmpz((s + j + k) % (2 ** num_bits_q))
            # Compute the hash of the argument
            hash_arg = sha1(to_binary(arg)).hexdigest()
            V.append(int(hash_arg, 16))
        
        # Compute W by summing up the values
        W = sum([V[qq] * 2 ** (160 * qq) for qq in range(num_blocks_p)])
        # Compute W for the last block
        W += (V[num_blocks_p] % 2 ** remaining_bits_p) * 2 ** (160 * num_blocks_p)
        # Compute X used for generating parameters p and q
        X = W + 2 ** (key_length - 1)
        # Compute c used for generating parameters p and q
        c = X % (2 * q)
        # Compute p - a prime number used for generating keys and verifying signatures
        p = X - c + 1

        # Check if p satisfies the conditions and is a prime number
        if p >= 2 ** (key_length - 1) and is_prime(p, 10):
            return p, q

        i += 1
        j += num_blocks_p + 1

# Function to generate private and public keys
def generate_keys(g, p, q):
    # Generate a private key
    private_key = randrange(2, q)
    # Compute a public key
    public_key = powmod(g, private_key, p)
    return private_key, public_key

# Function to generate generator g
def generate_g(p, q):
    while True:
        # Generate a random number h
        h = randrange(2, p - 1)
        # Compute exp
        exp = xmpz((p - 1) // q)
        # Compute generator g
        g = powmod(h, exp, p)
        if g > 1:
            break
    return g
# Function to generate parameters p, q, g
def generate_parameters(key_length, security_parameter):
    p, q = generate_p_q(key_length, security_parameter)
    g = generate_g(p, q)
    return p, q, g

# Function to sign a message
def sign(message, p, q, g, private_key):
    # Validate the parameters
    if not validate_parameters(p, q, g):
        raise Exception("Invalid parameters")

    while True:
        # Generate a random number k
        k = randrange(2, q)
        # Compute r
        r = powmod(g, k, p) % q
        # Compute the hash of the message
        message_hash = int(sha1(message).hexdigest(), 16)

        try:
            # Compute s
            s = (invert(k, q) * (message_hash + private_key * r)) % q
            return r, s
        except ZeroDivisionError:
            pass

# Function to verify a signature
def verify(message, r, s, p, q, g, public_key):
    # Validate the parameters
    if not validate_parameters(p, q, g):
        raise Exception("Invalid parameters")

    # Validate the signature
    if not validate_signature(r, s, q):
        return False

    try:
        # Compute w
        w = invert(s, q)
    except ZeroDivisionError:
        return False

    # Compute the hash of the message
    message_hash = int(sha1(message).hexdigest(), 16)
    # Compute u1 and u2 - intermediate values for signature verification
    u1 = (message_hash * w) % q
    u2 = (r * w) % q
    # Compute v obtained during signature verification
    v = (powmod(g, u1, p) * powmod(public_key, u2, p)) % p % q

    # Check the condition
    if v == r:
        return True
    return False

# Function to validate the signature
def validate_signature(r, s, q):
    if r < 0 and r > q:
        return False

    if s < 0 and s > q:
        return False

    return True

# Function to validate the parameters p, q, g
def validate_parameters(p, q, g):
    if is_prime(p) and is_prime(q):
        return True

    if powmod(g, q, p) == 1 and g > 1 and (p - 1) % q:
        return True

    return False

if __name__ == "__main__":
    security_parameter = 160
    key_length = 1024
    # Generate parameters p, q, g
    p, q, g = generate_parameters(key_length, security_parameter)
    # Generate private and public keys
    private_key, public_key = generate_keys(g, p, q)

    message = "Hello world!"
    message_bytes = str.encode(message, "ascii")
    # Sign the message
    r, s = sign(message_bytes, p, q, g, private_key)
    # Verify the signature
    if verify(message_bytes, r, s, p, q, g, public_key):
        print('All ok')

    print("Message:", message)
    print("Signature (r, s):", r, s)
    print("Public key (p, q, g, y):", p, q, g, public_key)
    print("Private key (x):", private_key)
