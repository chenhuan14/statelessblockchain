import secrets

from helpfunctions import concat, generate_two_large_distinct_primes, hash_to_prime, bezoute_coefficients,\
    mul_inv, shamir_trick, calculate_product

import time
import sys

from Crypto.PublicKey import RSA

RSA_KEY_SIZE = 3072  # RSA key size for 128 bits of security (modulu size)
RSA_PRIME_SIZE = int(RSA_KEY_SIZE / 2)
ACCUMULATED_PRIME_SIZE = 128  # taken from: LLX, "Universal accumulators with efficient nonmembership proofs", construction 1


def setup():
    # draw strong primes p,q
    p, q = generate_two_large_distinct_primes(RSA_PRIME_SIZE)
    n = p*q
    # draw random number within range of [0,n-1]
    A0 = secrets.randbelow(n)
    order = (p-1)*(q-1)
    return n, A0, dict(), order


def add(A, S, x, n):
    if x in S.keys():
        return A
    else:
        hash_prime, nonce = hash_to_prime(x, ACCUMULATED_PRIME_SIZE)
        A = pow(A, hash_prime, n)
        S[x] = nonce
        return A


def batch_add(A_pre_add, S, x_list, n, order):
    product = 1
    for x in x_list:
        if x not in S.keys():
            hash_prime, nonce = hash_to_prime(x, ACCUMULATED_PRIME_SIZE)
            S[x] = nonce
            product = product * hash_prime % order
    A_post_add = pow(A_pre_add, product, n)
    return A_post_add, prove_exponentiation(A_pre_add, product, A_post_add, n)


def prove_membership(A0, S, x, n):
    if x not in S.keys():
        return None
    else:
        product = 1
        for element in S.keys():
            if element != x:
                nonce = S[element]
                product *= hash_to_prime(element, ACCUMULATED_PRIME_SIZE, nonce)[0]
        A = pow(A0, product, n)
        return A


def prove_non_membership(A0, S, x, x_nonce, n, order):
    if x in S.keys():
        return None
    else:
        product = 1
        for element in S.keys():
            nonce = S[element]
            product *= hash_to_prime(element, ACCUMULATED_PRIME_SIZE, nonce)[0]
    prime = hash_to_prime(x, ACCUMULATED_PRIME_SIZE, x_nonce)[0]

    print("product:", sys.getsizeof(product))
    tik = time.time()
    a, b = bezoute_coefficients(prime, product)
    if a < 0:
        positive_a = -a % order
        inverse_A0 = mul_inv(A0, n)
        d = pow(inverse_A0, positive_a, n)
    else:
        d = pow(A0, a % order, n)

    tok = time.time()
    print("bezout:", tok-tik)
    return d, b





def verify_non_membership(A0, A_final, d, b, x, x_nonce, n):
    prime = hash_to_prime(x, ACCUMULATED_PRIME_SIZE, x_nonce)[0]
    if b < 0:
        positive_b = -b
        inverse_A_final = mul_inv(A_final, n)
        second_power = pow(inverse_A_final, positive_b, n)
    else:
        second_power = pow(A_final, b, n)
    return (pow(d, prime, n) * second_power) % n == A0


def batch_prove_membership(A0, S, x_list, n):
    product = 1
    for element in S.keys():
        if element not in x_list:
            nonce = S[element]
            product *= hash_to_prime(element, ACCUMULATED_PRIME_SIZE, nonce)[0]
    A = pow(A0, product, n)
    return A


def batch_prove_membership_with_NIPoE(A0, S, x_list, n, w):
    u = batch_prove_membership(A0, S, x_list, n)
    nonces_list = []
    for x in x_list:
        nonces_list.append(S[x])
    product = __calculate_primes_product(x_list, nonces_list)
    (Q, l_nonce) = prove_exponentiation(u, product, w, n)
    return Q, l_nonce, u


def prove_membership_with_NIPoE(g, S, x, n, w):
    u = prove_membership(g, S, x, n)
    x_prime, x_nonce = hash_to_prime(x=x, nonce=S[x])
    (Q, l_nonce) = prove_exponentiation(u, x_prime, w, n)
    return Q, l_nonce, u




# NI-PoE: non-interactive version of section 3.1 in BBF18 (PoE).
# Receives:
#   u - the accumulator value before add
#   x - the (prime) element which was added to the accumulator
#   w - the accumulator after the addition of x
#   n - the modulu
# Returns:
#   Q, x - the NIPoE
#   nonce - the nonce used for hash_to_prime to receive l (for saving work to the verifier)
def prove_exponentiation(u, x, w, n):
    l, nonce = hash_to_prime(concat(x, u, w))  # Fiat-Shamir instead of interactive challenge
    q = x // l
    Q = pow(u, q, n)
    return Q, nonce


# Verify NI-PoE
# we pass the l_nonce just for speed up. The verifier has to reproduce l himself.
def verify_exponentiation(Q, l_nonce, u, x, x_nonce, w, n):
    x = hash_to_prime(x=x, nonce=x_nonce)[0]
    return __verify_exponentiation(Q, l_nonce, u, x, w, n)


def batch_verify_membership_with_NIPoE(Q, l_nonce, u, x_list, x_nonces_list, w, n):
    product = __calculate_primes_product(x_list, x_nonces_list)
    return __verify_exponentiation(Q, l_nonce, u, product, w, n)


# helper function, does not do hash_to_prime on x
def __verify_exponentiation(Q, l_nonce, u, x, w, n):
    l = hash_to_prime(x=(concat(x, u, w)), nonce=l_nonce)[0]
    r = x % l
    # check (Q^l)(u^r) == w
    return (pow(Q, l, n) % n) * (pow(u, r, n) % n) % n == w


def delete(A0, A, S, x, n):
    if x not in S.keys():
        return A
    else:
        del S[x]
        product = 1
        for element in S.keys():
            nonce = S[element]
            product *= hash_to_prime(element, ACCUMULATED_PRIME_SIZE, nonce)[0]
        Anew = pow(A0, product, n)
        return Anew


# x_list are in S
def batch_delete(A0, S, x_list, n):
    for x in x_list:
        del S[x]
    product = 1
    for element in S.keys():
            nonce = S[element]
            product *= hash_to_prime(element, ACCUMULATED_PRIME_SIZE, nonce)[0]
    Anew = pow(A0, product, n)
    return Anew


# agg_indexes: in case proofs_list actually relate to some aggregation of the inputs in x_list, it should contain pairs
# of start index and end index.
def batch_delete_using_membership_proofs(A_pre_delete, S, x_list, proofs_list, n, agg_indexes=[]):
    is_aggregated = len(agg_indexes) > 0
    if is_aggregated and len(proofs_list) != len(agg_indexes):
        return None

    if (not is_aggregated) and len(x_list) != len(proofs_list):
        return None

    members = []
    if is_aggregated:
        # sanity - verify each and every proof individually
        for i, indexes in enumerate(agg_indexes):
            current_x_list = x_list[indexes[0]: indexes[1]]
            current_nonce_list = [S[x] for x in current_x_list]
            product = __calculate_primes_product(current_x_list, current_nonce_list)
            members.append(product)
            for x in current_x_list:
                del S[x]
    else:
        for x in x_list:
            members.append(hash_to_prime(x, ACCUMULATED_PRIME_SIZE, S[x])[0])
            del S[x]

    A_post_delete = proofs_list[0]
    product = members[0]

    for i in range(len(members))[1:]:
        A_post_delete = shamir_trick(A_post_delete, proofs_list[i], product, members[i], n)
        product *= members[i]

    return A_post_delete, prove_exponentiation(A_post_delete, product, A_pre_delete, n)


def verify_membership(A, x, nonce, proof, n):
    return __verify_membership(A, hash_to_prime(x=x, num_of_bits=ACCUMULATED_PRIME_SIZE, nonce=nonce)[0], proof, n)


def batch_verify_membership(A, x_list, nonce_list, proof, n):
    product = __calculate_primes_product(x_list, nonce_list)
    return __verify_membership(A, product, proof, n)


def __calculate_primes_product(x_list, nonce_list):
    if len(x_list) != len(nonce_list):
        return None

    primes_list = [hash_to_prime(x, nonce=nonce_list[i])[0] for i, x in enumerate(x_list)]
    product = calculate_product(primes_list)
    return product


# helper function, does not do hash to prime.
def __verify_membership(A, x, proof, n):
    return pow(proof, x, n) == A


def create_all_membership_witnesses(A0, S, n):
    primes = [hash_to_prime(x=x, nonce=S[x])[0] for x in S.keys()]
    return root_factor(A0, primes, n)


def root_factor(g, primes, N):
    n = len(primes)
    if n == 1:
        return [g]

    n_tag = n // 2
    primes_L = primes[n_tag:n]
    product_L = calculate_product(primes_L)
    g_L = pow(g, product_L, N)

    primes_R = primes[0: n_tag]
    product_R = calculate_product(primes_R)
    g_R = pow(g, product_R, N)

    L = root_factor(g_L, primes_R, N)
    R = root_factor(g_R, primes_L, N)

    return L + R


def aggregate_membership_witnesses(A, witnesses_list, x_list, nonces_list, n):
    primes = []
    for i in range(len(x_list)):
        prime = hash_to_prime(x_list[i], ACCUMULATED_PRIME_SIZE, nonces_list[i])[0]
        primes.append(prime)

    agg_wit = witnesses_list[0]
    product = primes[0]

    for i in range(len(x_list))[1:]:
        agg_wit = shamir_trick(agg_wit, witnesses_list[i], product, primes[i], n)
        product *= primes[i]

    return agg_wit, prove_exponentiation(agg_wit, product, A, n)


# update witness for rsa accumulator on add a single element
def acc_add_witness_update(S, x, x_old_proof, x_add, x_nonce, n):
    if x == x_add:
        return
    if x not in S.keys():
        return
    hash_prime, _ = hash_to_prime(x_add, ACCUMULATED_PRIME_SIZE, x_nonce)
    return pow(x_old_proof, hash_prime, n)


# update witness for rsa accumulator on add multiple elements
def acc_batch_add_witness_update(S, x, x_old_proof, x_list, n):
    if x in x_list:
        return

    product = 1
    for i in range(len(x_list)):
        if x_list[i] not in S.keys():
            prime = hash_to_prime(x_list[i], ACCUMULATED_PRIME_SIZE,0)[0]
            product *= prime
    return pow(x_old_proof, product, n)


# LLX 2007
# x and x_del should call hash_to_prime first.


def acc_del_mem_witness_update(x, x_old_proof, x_del, A_final, n):
    return __acc_del_mem_witness_update_prime(hash_to_prime(x, ACCUMULATED_PRIME_SIZE)[0],
                                          x_old_proof,
                                          hash_to_prime(x_del, ACCUMULATED_PRIME_SIZE)[0],
                                          A_final, n)


def acc_batch_del_mem_witness_update(x, x_old_proof, x_del_list, A_final, n):
    if x in x_del_list:
        return

    product = 1
    for i in range(len(x_del_list)):
        prime = hash_to_prime(x_del_list[i], ACCUMULATED_PRIME_SIZE)[0]
        product *= prime

    return __acc_del_mem_witness_update_prime(hash_to_prime(x, ACCUMULATED_PRIME_SIZE)[0], x_old_proof, product, A_final, n)


def __acc_del_mem_witness_update_prime(x_prime, x_old_proof, x_del_prime, A_final, n):
    if x_prime == x_del_prime:
        return

    a, b = bezoute_coefficients(x_prime, x_del_prime)
    if a < 0:
        positive_a = -a
        inverse_A_final = mul_inv(A_final, n)
        first_power = pow(inverse_A_final, positive_a, n)

        second_power = pow(x_old_proof, b, n)
    elif b < 0:
        first_power = pow(A_final, a, n)

        positive_b = -b
        inverse_proof = mul_inv(x_old_proof, n)
        second_power = pow(inverse_proof, positive_b, n)
    return first_power * second_power % n


def __acc_add_non_membership_witness_update_prime(A, S, x_prime, d, b, x_add_prime, n, order):

    tik = time.time()
    a0, b0 = bezoute_coefficients(x_prime, x_add_prime)
    tok = time.time()
    print("bezout:", tok-tik)

    tik = time.time()
    r = a0 * b
    if r < 0:
        inverse_r = -r % order
        inverse_A = mul_inv(A, n)

        d = d * pow(inverse_A, inverse_r, n)
    else:
        r = r % order
        d = d * pow(A, r, n)

    b = (b0 * b)
    print("d size:", sys.getsizeof(d))
    print("b size:", sys.getsizeof(b))
    tok = time.time()
    print("update:", tok - tik)

    return d, b




def acc_add_non_membership_witness_update(A, S, x, d, b, x_add, n):
    if x in S.keys():
        return

    x_prime = hash_to_prime(x, ACCUMULATED_PRIME_SIZE)[0]
    x_add_prime = hash_to_prime(x_add, ACCUMULATED_PRIME_SIZE)[0]

    d, b = __acc_add_non_membership_witness_update_prime(A, S, x_prime, d, b, x_add_prime, n)
    return d, b


# uncheck whether add_list elements in S
def acc_batch_add_non_membership_witness_update(A, S, x, d, b, add_list, n):
    if x in S.keys():
        return

    product = calculate_primes_product(add_list, n)

    x_prime = hash_to_prime(x, ACCUMULATED_PRIME_SIZE)[0]

    d, b = __acc_add_non_membership_witness_update_prime(A, S, x_prime, d, b, product, n)
    return d, b


def acc_batch_add_prime_non_membership_witness_update(A, S, x, d, b, add_list_prime, n, order):
    if x in S.keys():
        return

    x_prime = hash_to_prime(x, ACCUMULATED_PRIME_SIZE)[0]

    d, b = __acc_add_non_membership_witness_update_prime(A, S, x_prime, d, b, add_list_prime, n, order)
    return d, b


def calculate_primes_product(x_list, n):
    product = 1
    for i in range(len(x_list)):
        prime = hash_to_prime(x_list[i], ACCUMULATED_PRIME_SIZE)[0]
        product *= prime
    return product


# def gen_non_membership_by_VB(x_prime, x_list_prime):
#     product = 1
#     for e in x_list_prime:
#         product = product * e % x_prime
#     return x_prime - product

#def verify_non_membership_by_VB(A_pre, A_post, x_prime, x_list_primes, g):



