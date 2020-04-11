from time import time
from Crypto.PublicKey import RSA
from rsa_psi import client, server, utils


DEBUG = True


def timer(func):
    if not DEBUG:
        return func

    def wrapper(*args, **kwargs):
        t_start = time()
        result = func(*args, **kwargs)
        t_end = time()

        t_diff = t_end - t_start
        print(f"[+] function '{func.__name__}' took {t_diff * 1000}ms")

        return result

    return wrapper


@timer
def generate_private_key(n_bits, exponent):
    key = RSA.generate(n_bits, e=exponent)
    return key


@timer
def main(X, Y, eps=utils.eps, m=utils.m, e=utils.e):
    # BASE
    private_key = generate_private_key(m, e)
    public_key = RSA.construct((private_key.n, private_key.e))
    random_factors = client.generate_random_factors(public_key)
    # SETUP
    bf = server.setup_bf(private_key, X)
    # ONLINE
    A = client.blind_batch(Y, random_factors)
    B = server.sign_batch(private_key, A)
    X_Y = client.intersect(Y, B, random_factors, bf, public_key)

    return X_Y


if __name__ == "__main__":
    X = list(range(0, 2**10, 5))
    Y = list(range(0, 2**20))
    X_Y = main(X, Y)
    print(f"[+] intersection is: {X_Y}")
