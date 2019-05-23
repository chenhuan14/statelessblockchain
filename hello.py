
from Crypto.PublicKey import RSA
import random




def main():
    a = 2
    if a > 1:
        first = 1
    else:
        first = 2
    print(first)

    print("hello python!")

    key = RSA.generate(1024)

    a = random.randint(1, pow(2, 256))
    b = random.randint(1, pow(2, 256))

    c_a = pow(a, key.e, key.n)
    c_b = pow(b, key.e, key.n)

    c_ab = pow(a*b % key.n, key.e, key.n)

    print(c_a*c_b % key.n == c_ab)




if __name__ == "__main__":
    main()