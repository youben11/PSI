import secrets
from rsa_psi import utils


NC_MAX = 1024


def _rand_factor(n):
    return secrets.randbelow(n)


def generate_random_factors(public_key):
    random_factors = []
    for _ in range(NC_MAX):
        r = _rand_factor(public_key.n)
        r_inv = utils.inverse(public_key, r)
        r_encrypted = utils.encrypt(public_key, r)
        random_factors.append((r_inv, r_encrypted))

    return random_factors


def blind_batch(Y, random_factors):
    A = []
    for y, rf in zip(Y, random_factors):
        r_encrypted = rf[1]
        A.append(y * r_encrypted)
    return A


def intersect(Y, B, random_factors, bf, public_key):
    n = public_key.n
    result = []
    for y, b, rf in zip(Y, B, random_factors):
        r_inv = rf[0]
        to_check = (b * r_inv) % n
        if to_check in bf:
            result.append(y)
    return result
