#  Copyright (c) 2022. Illia Popov.

import random
import sha1
import secrets


def is_prime(n, k=10):
    # Miller-Rabin Primality Test

    if n < 2:
        return False

    r = 0
    d = n - 1
    while d % 2 == 0:
        d = d // 2
        r += 1

    for _ in range(k):

        a = random.randrange(2, n - 1)

        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == 1:
                return False

            if x == n - 1:
                break
        else:
            return False

    return True


def generate_primes(bit_length):
    # p > q (same bit length)

    while True:
        p = secrets.randbits(bit_length)
        p = p | 1 << (bit_length - 1)

        if is_prime(p):
            break

    while True:
        q = secrets.randbits(bit_length)
        q = q | 1 << (bit_length - 1)

        if is_prime(q):
            break

    return max(p, q), min(p, q)


def extended_euclidean_algorithm(a, b):
    if a == 0:
        return 0, 1
    else:
        x, y = extended_euclidean_algorithm(b % a, a)
        return y - (b // a) * x, x


def create_keys(key_bit_length):
    while True:
        p, q = generate_primes(key_bit_length // 2)

        if (p * q).bit_length() == key_bit_length:
            break

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = extended_euclidean_algorithm(e, phi)[0] % phi

    return (n, e), (n, d)


def create_digital_signature(message_to_sign, private_key):
    message_hash = int(sha1.sha1_hash(message_to_sign), 16)

    n, d = private_key

    signature = pow(message_hash, d, n)

    return signature


def verify_signature(message_to_verify, signature, public_key):
    n, e = public_key

    v = pow(signature, e, n)

    verifying_message_hash = int(sha1.sha1_hash(message_to_verify), 16)

    if verifying_message_hash == v:
        return True
    else:
        return False


if __name__ == '__main__':
    public_key, private_key = create_keys(1024)
    message = input()

    sign = create_digital_signature(message, private_key)
    result = verify_signature(message, sign, public_key)
    print(f'Signature valid: {result}')

    #changed message
    message_changed = message + "smth"
    result = verify_signature(message_changed, sign, public_key)
    print(f'Signature valid (changed message): {result}')

    #changed public key
    public_key_new = create_keys(1024)[0]
    result = verify_signature(message_changed, sign, public_key_new)
    print(f'Signature valid (changed key): {result}')

