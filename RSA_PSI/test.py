from time import time
from Crypto.PublicKey import RSA
from io import BytesIO
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
        print(f"[TIMER] function '{func.__name__}' took {t_diff * 1000}ms")

        return result

    return wrapper


# wrap some functions with the timer
if DEBUG:
    server.setup_bf = timer(server.setup_bf)
    server.sign_batch = timer(server.sign_batch)
    client.blind_batch = timer(client.blind_batch)
    client.intersect = timer(client.intersect)


@timer
def generate_private_key(n_bits, exponent):
    key = RSA.generate(n_bits, e=exponent)
    return key


@timer
def main(X, Y, eps=utils.eps, m=utils.m, e=utils.e):
    # INPUT
    print(f"[INPUT] server and client sets size: {len(X)} and {len(Y)}")
    # BASE
    private_key = generate_private_key(m, e)
    public_key = RSA.construct((private_key.n, private_key.e))
    random_factors = client.generate_random_factors(public_key)
    # SETUP
    bf = server.setup_bf(private_key, X)
    f = BytesIO()
    utils.save_bf(bf, f)
    size = f.tell()
    print(f"[SETUP] server --> client: {size} bytes")
    # ONLINE
    A = client.blind_batch(Y, random_factors, public_key.n)
    print(f"[ONLINE] client <--> server (x2): {len(A) * m // 8} bytes")
    B = server.sign_batch(private_key, A)
    X_Y = client.intersect(Y, B, random_factors, bf, public_key)

    return X_Y


if __name__ == "__main__":
    X = list(range(0, 2**10))
    Y = list(range(0, 2**10, 5))
    X_Y = main(X, Y)
    print(f"[OUTPUT] intersection set size: {len(X_Y)}")
