
import time
from main import setup, batch_add, batch_prove_membership, batch_prove_membership_with_NIPoE, \
    batch_verify_membership, batch_verify_membership_with_NIPoE, batch_delete_using_membership_proofs, \
    prove_membership, batch_delete, acc_batch_del_mem_witness_update, verify_membership, acc_batch_add_witness_update, \
    hash_to_prime, bezoute_coefficients

import random


# add (for all new utxos in block)
acc_batch_add_genesis_timing = []
acc_batch_add_per_block_timing = []

# delete (for all spent txos in block)
acc_delete_timing = []
acc_batch_delete_timing = []

# prove membership
acc_prove_mem_timing = []
acc_prove_mem_with_NIPoE_timing = []
acc_batch_prove_mem_timing = []
acc_batch_prove_mem_with_NIPoE_timing = []

# verify membership ; per tx
acc_verify_mem_per_tx_timing = []
acc_verify_mem_with_NIPoE_per_tx_timing = []
acc_batch_verify_mem_per_tx_timing = []
acc_batch_verify_mem_with_NIPoE_per_tx_timing = []

# verify membership per block
acc_verify_mem_per_block_timing = []
acc_verify_mem_with_NIPoE_per_block_timing = []
acc_batch_verify_mem_per_block_timing = []
acc_batch_verify_mem_with_NIPoE_per_block_timing = []

# verify aggregated 2 NI-PoE inclusion proofs after block mining
acc_batch_verify_two_NIPoE_post_mining = []

acc_create_all_membership_witness = []

GENERATED_CSV_DIRECTORY = 'result-rsa-add-del'

def create_random_list(size):
    result = []
    for index in range(0, size):
        random_element = random.randint(1, pow(2, 256))
        result.append(random_element)
    return result


def test_batch_add(total_utxo_set_size_for_accumulator, add_element_size):
    print("--> initialize and fill up accumulator state")
    n, A0, S = setup()

    elements_for_accumulator = create_random_list(total_utxo_set_size_for_accumulator)

    tik = time.time()
    A1, proof1 = batch_add(A0, S, elements_for_accumulator, n)
    tok = time.time()
    acc_batch_add_genesis_timing.append(tok - tik)
    print("<--   Done.", acc_batch_add_genesis_timing[-1])

    add_elements = create_random_list(add_element_size)
    print("--> ADD elements to accumulator")
    tik = time.time()
    A2, proof2= batch_add(A1, S, add_elements, n)
    tok =  time.time()
    print("<-- Done", tok - tik)

    nonces_list = []
    for x in add_elements:
        _, nonce = hash_to_prime(x=x, nonce=0)
        nonces_list.append(nonce)


    print("--> verify NI_POES")
    tik = time.time()
    print(batch_verify_membership_with_NIPoE(proof2[0], proof2[1], A1, add_elements,
                                                nonces_list, A2, n))
    tok = time.time()
    print("<-- Done", tok - tik)


#test_batch_add(10, 1000)
print(bezoute_coefficients(7,11))
print(bezoute_coefficients(5,29))
print(bezoute_coefficients(5,17*29))