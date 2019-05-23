import sys
from helpfunctions import hash_to_prime,xgcd
import random
from main import setup
import time


def create_random_list(size):
    result = []
    for index in range(0, size):
        random_element = random.randint(1, pow(2, 256))
        result.append(random_element)
    return result



n,A0,S = setup()
cache = {}
elememts = create_random_list(1000)
product = 1
for ele in elememts:
    product *= ele

tik = time.time()
ser = pow(A0, product,n)
tok = time.time()

print("ser:", tok -tik)
print("size:", sys.getsizeof(product))

















