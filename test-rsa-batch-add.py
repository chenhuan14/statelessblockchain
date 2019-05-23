
import time
from main import setup, batch_add, batch_prove_membership, batch_prove_membership_with_NIPoE, \
    batch_verify_membership, batch_verify_membership_with_NIPoE, batch_delete_using_membership_proofs, \
    prove_membership, batch_delete, acc_batch_del_mem_witness_update, verify_membership, acc_batch_add_witness_update

import csv
import os
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


def test_batch_del_add(total_utxo_set_size_for_accumulator, num_of_inputs_in_tx, num_of_outputs_in_tx, num_of_txs_in_block):
    print("----------------------")
    print("total_utxo_set_size_for_accumulator =", total_utxo_set_size_for_accumulator)
    print("num_of_inputs_in_tx =", num_of_inputs_in_tx)
    print("num_of_outputs_in_tx =", num_of_outputs_in_tx)
    print("num_of_txs_in_block =", num_of_txs_in_block)

    print("--> initialize and fill up accumulator state")
    n, A0, S = setup()
    if total_utxo_set_size_for_accumulator < num_of_inputs_in_tx * num_of_txs_in_block:
        print("please select larger total_utxo_set_size_for_accumulator.")
        return None
    elements_for_accumulator = create_random_list(total_utxo_set_size_for_accumulator)
    inputs_for_accumulator = elements_for_accumulator[0:(num_of_inputs_in_tx * num_of_txs_in_block)]
    outputs_for_accumulator = create_random_list(num_of_outputs_in_tx * num_of_txs_in_block)
    tik = time.time()
    A_post_batch_add, proof = batch_add(A0, S, elements_for_accumulator, n)
    inputs_nonces_list = [S[x] for x in inputs_for_accumulator]
    tok = time.time()
    acc_batch_add_genesis_timing.append(tok - tik)
    print("<--   Done.", acc_batch_add_genesis_timing[-1])

    print("--> prove membership accumulator")
    times = []
    acc_mem_proofs = []
    for i in range(num_of_txs_in_block):
        tik = time.time()
        inputs_list = []
        for j in range(num_of_inputs_in_tx):
            inputs_list.append(inputs_for_accumulator[num_of_inputs_in_tx * i + j])
        acc_mem_proofs.append(batch_prove_membership(A0, S, inputs_list, n))
        tok = time.time()
        times.append(tok - tik)
    sum_times = sum(times)
    acc_batch_prove_mem_timing.append(sum_times / len(times))  # average
    print("<--   Done. total:", sum_times, "; per tx:", acc_batch_prove_mem_timing[-1])

    print("--> prove membership accumulator with NI-PoE")
    times = []
    acc_mem_proofs_with_NIPoE = []
    for i in range(num_of_txs_in_block):
        tik = time.time()
        inputs_list = []
        for j in range(num_of_inputs_in_tx):
            inputs_list.append(inputs_for_accumulator[num_of_inputs_in_tx * i + j])
        acc_mem_proofs_with_NIPoE.append(batch_prove_membership_with_NIPoE(A0, S, inputs_list, n, A_post_batch_add))
        tok = time.time()
        times.append(tok - tik)
    sum_times = sum(times)
    acc_batch_prove_mem_with_NIPoE_timing.append(sum_times / len(times))  # average
    print("<--   Done. total:", sum_times, "; per tx:", acc_batch_prove_mem_with_NIPoE_timing[-1])


    print("--> accumulator batch verify membership")
    tik = time.time()
    for i in range(num_of_txs_in_block):
        inputs_list = []
        for j in range(num_of_inputs_in_tx):
            inputs_list.append(inputs_for_accumulator[num_of_inputs_in_tx * i + j])
        # TODO: nonces should be given by the proofs?
        nonces_list = list(map(lambda x: S[x], inputs_list))
        assert batch_verify_membership(A_post_batch_add, inputs_list, nonces_list, acc_mem_proofs[i], n)
    tok = time.time()
    acc_batch_verify_mem_per_block_timing.append(tok - tik)
    acc_batch_verify_mem_per_tx_timing.append((tok - tik) / num_of_txs_in_block)  # average
    print("<--   Done. total (per block):", acc_batch_verify_mem_per_block_timing[-1], "; per tx:",
          acc_batch_verify_mem_per_tx_timing[-1])

    print("--> accumulator batch verify membership with NIPoE")
    tik = time.time()
    for i in range(num_of_txs_in_block):
        inputs_list = []
        for j in range(num_of_inputs_in_tx):
            inputs_list.append(inputs_for_accumulator[num_of_inputs_in_tx * i + j])
        # TODO: nonces should be given by the proofs?
        nonces_list = list(map(lambda x: S[x], inputs_list))
        assert batch_verify_membership_with_NIPoE(
            acc_mem_proofs_with_NIPoE[i][0],
            acc_mem_proofs_with_NIPoE[i][1],
            acc_mem_proofs_with_NIPoE[i][2],
            inputs_list,
            nonces_list,
            A_post_batch_add,
            n)
    tok = time.time()
    acc_batch_verify_mem_with_NIPoE_per_block_timing.append(tok - tik)
    acc_batch_verify_mem_with_NIPoE_per_tx_timing.append((tok - tik) / num_of_txs_in_block)  # average
    print("<--   Done. total (per block):", acc_batch_verify_mem_with_NIPoE_per_block_timing[-1], "; per tx:",
          acc_batch_verify_mem_with_NIPoE_per_tx_timing[-1])

    print("--> accumulator batch delete spent TXOs + first NI-PoE")
    tik = time.time()
    agg_inputs_indexes = []
    for i in range(num_of_txs_in_block):
        agg_inputs_indexes.append([num_of_inputs_in_tx * i, num_of_inputs_in_tx * (i + 1)])
    # TODO: can we get the NI-PoE proofs here?
    A_post_batch_delete, niope1 = batch_delete_using_membership_proofs(A_post_batch_add, S, inputs_for_accumulator,
                                                                       acc_mem_proofs, n, agg_inputs_indexes)
    tok = time.time()
    acc_batch_delete_timing.append(tok - tik)
    print("<--   Done.", acc_batch_delete_timing[-1])

    print("--> accumulator batch add new UTXOs + second NI-PoE")
    tik = time.time()
    A_post_batch_add_new, niope2 = batch_add(A_post_batch_delete, S, outputs_for_accumulator, n)
    outputs_nonces_list = [S[x] for x in outputs_for_accumulator]
    tok = time.time()
    acc_batch_add_per_block_timing.append(tok - tik)
    print("<--   Done.", acc_batch_add_per_block_timing[-1])

    print("--> accumulator verify first NI-PoE & second NI-PoE")
    tik = time.time()
    assert batch_verify_membership_with_NIPoE(niope1[0], niope1[1], A_post_batch_delete, inputs_for_accumulator,
                                              inputs_nonces_list, A_post_batch_add, n)
    assert batch_verify_membership_with_NIPoE(niope2[0], niope2[1], A_post_batch_delete, outputs_for_accumulator,
                                              outputs_nonces_list, A_post_batch_add_new, n)
    tok = time.time()
    acc_batch_verify_two_NIPoE_post_mining.append(tok - tik)
    print("<--   Done.", acc_batch_verify_two_NIPoE_post_mining[-1])


def test_witness_update_on_del_add(total_utxo_set_size_for_accumulator, delete_element_size, add_element_size):

    if delete_element_size >= total_utxo_set_size_for_accumulator:
        print("delete element size should smaller than total_utxo_set_size")

    print("total_utxo_set_size_for_accumulator =", total_utxo_set_size_for_accumulator)

    print("--> initialize and fill up accumulator state")
    n, A0, S = setup()
    elements_for_accumulator = create_random_list(total_utxo_set_size_for_accumulator)
    tik = time.time()
    A_post, _ = batch_add(A0, S, elements_for_accumulator, n)
    tok = time.time()
    print("<--   Done.", tok - tik)


    print("--> generate the last element proof")
    tik = time.time()
    last_element = elements_for_accumulator[-1]
    last_element_proof = prove_membership(A0, S, elements_for_accumulator[-1], n)
    tok = time.time()
    print("<-- Done.", tok-tik)

    print("--> delete elements")
    delete_elements = []
    for i in range(delete_element_size):
        delete_elements.append(elements_for_accumulator[i])
    A_post_del = batch_delete(A0, S, delete_elements,n)
    print("<--  Done.")

    print("--> witness update on batch delete")
    tik = time.time()
    new_proof_del = acc_batch_del_mem_witness_update(last_element, last_element_proof, delete_elements, A_post_del, n)
    tok = time.time()
    print("<-- Done.", tok - tik)

    print("--> verify new proof")
    result = verify_membership(A_post_del, last_element, S[last_element], new_proof_del, n)
    print("Done")
    print(result)

    elements_for_add = create_random_list(add_element_size)
    print("--> witness update on batch add")
    tik = time.time()
    acc_batch_add_witness_update(S, last_element, new_proof_del, elements_for_add, n)
    tok = time.time()
    print("<-- Done.", tok-tik)


test_witness_update_on_del_add(500, 300, 300)

# num_of_txs_in_block = []
# for i in range(5):
#     num_of_txs_in_block.append((i + 1) * 20)
#     test_batch_del_add(
#         total_utxo_set_size_for_accumulator=num_of_txs_in_block[i] * 3,
#         num_of_inputs_in_tx=3,
#         num_of_outputs_in_tx=3,
#         num_of_txs_in_block=num_of_txs_in_block[i])
#
#
#
# num_of_txs_in_block = [''] + num_of_txs_in_block
#
# with open(GENERATED_CSV_DIRECTORY + '/proofs-per-tx.csv', mode='w') as csv_file:
#     csv_file = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
#     csv_file.writerow(num_of_txs_in_block)
#     csv_file.writerow(['Accumulator: Aggregate'] + acc_batch_prove_mem_timing)
#     csv_file.writerow(['Accumulator: Aggregate w. NI-PoE'] + acc_batch_prove_mem_with_NIPoE_timing)
#
# with open(GENERATED_CSV_DIRECTORY + '/verifications-per-tx.csv', mode='w') as csv_file:
#     csv_file = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
#     csv_file.writerow(num_of_txs_in_block)
#     csv_file.writerow(['Accumulator: Batch'] + acc_batch_verify_mem_per_tx_timing)
#     csv_file.writerow(['Accumulator: Batch w. NI-PoE'] + acc_batch_verify_mem_with_NIPoE_per_tx_timing)
#
# with open(GENERATED_CSV_DIRECTORY + '/verifications-per-block.csv', mode='w') as csv_file:
#     csv_file = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
#     csv_file.writerow(num_of_txs_in_block)
#     csv_file.writerow(['Accumulator: Batch'] + acc_batch_verify_mem_per_block_timing)
#     csv_file.writerow(['Accumulator: Batch w. NI-PoE'] + acc_batch_verify_mem_with_NIPoE_per_block_timing)
#
# with open(GENERATED_CSV_DIRECTORY + '/batch-delete-per-block.csv', mode='w') as csv_file:
#     csv_file = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
#     csv_file.writerow(num_of_txs_in_block)
#     csv_file.writerow(['Accumulator: Batch Delete'] + acc_batch_delete_timing)
#
# with open(GENERATED_CSV_DIRECTORY + '/batch-add-per-block.csv', mode='w') as csv_file:
#     csv_file = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
#     csv_file.writerow(num_of_txs_in_block)
#     csv_file.writerow(['Accumulator: Batch Add'] + acc_batch_add_per_block_timing)
#
# with open(GENERATED_CSV_DIRECTORY + '/batch-verify-aggregated-two-niopes.csv', mode='w') as csv_file:
#     csv_file = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
#     csv_file.writerow(num_of_txs_in_block)
#     csv_file.writerow(['Accumulator: Verify 2 NIPoEs'] + acc_batch_verify_two_NIPoE_post_mining)
#
# print('Done - written results to ' + os.path.dirname(os.path.abspath(__file__)) + '/' + GENERATED_CSV_DIRECTORY)

