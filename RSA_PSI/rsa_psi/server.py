from rsa_psi import utils


def setup_bf(private_key, X):
    bf = utils.new_bf()
    for x in X:
        bf.add(utils.sign(private_key, x))
    return bf


def sign_batch(private_key, A):
    B = []
    for a in A:
        B.append(utils.sign(private_key, a))
    return B
