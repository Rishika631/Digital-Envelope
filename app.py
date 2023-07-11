import os
import time
import uuid
import hashlib
from pyfiglet import Figlet
from caesarcipher import CaesarCipher
import streamlit as st

def gcd(num1, num2):
    while num2:
        num1, num2 = num2, (num1 % num2)
    return num1

def modInverse(num1, num2):
    num1 = num1 % num2
    for i in range(1, num2):
        if (num1 * i) % num2 == 1:
            return i

def hashing(word):
    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + word.encode()).hexdigest() + ':' + salt

def CompareHash(hashed_msz, decoded_msz):
    return hashed_msz == decoded_msz

def Input_data():
    p = st.number_input("Please Enter value of p [Prime number. eg. 7]: ")
    q = st.number_input("Please Enter value of q [Prime number. eg. 5]: ")
    common_key = st.number_input("Please enter the common key to be shared: ")
    st.write("\nThanks!")
    return p, q, common_key

def RSAKeyGeneration(p, q):
    n = p * q
    totient_func = (p - 1) * (q - 1)
    flag = 1
    while flag:
        e = st.number_input("Please select value of e: ")
        if gcd(totient_func, e) != 1:
            st.write("\nGCD of totient_func and e should be 1 (Relatively prime).")
            st.write("Please try again!")
            continue
        flag = 0
    if e > 1 and e < totient_func:
        d = modInverse(e, totient_func)
        st.write(f"\nValue of computed d is: {d}")
        st.write(f"Public Key here is - PU({e},{n})")
        st.write(f"Private Key here is - PR({d},{n})")
        return n, e, d

def RSAEncryption(e, n, common_key):
    cipher = pow(common_key, e, n)
    st.write(f"\nCipher text generated is: {cipher}")
    return cipher

def SymmetricEncryption(common_key):
    message = st.text_input("Please enter the message to be shared:")
    hashed_msz = hashing(message)
    encoded_msz = CaesarCipher(key=common_key).encipher(hashed_msz)
    st.write(f"\nHash for message given is: {hashed_msz}")
    st.write(f"Symmetrically encrypted data is: {encoded_msz}")
    return hashed_msz, encoded_msz

def RSADecryption(n, d, cipher, common_key):
    decipher = pow(cipher, d, n)
    st.write(f"\nDeciphered Common key is {decipher}")
    if decipher == common_key:
        st.write("Which match the sent key -", common_key)
    return decipher

def SymmetricDecryption(hashed_msz, encoded_msz, decipher):
    decoded_msz = CaesarCipher(key=decipher).decipher(encoded_msz)
    st.write(f"\nDecrypted hash message is: {decoded_msz}\n")
    st.write("##### RESULT #####")
    if CompareHash(hashed_msz, decoded_msz):
        st.write("--> The hash is same. The data is correct.")
    else:
        st.write("--> The hash is different. The data is incorrect")

def main():
    st.header("RSA Encryption and Decryption")
    die = True
    try:
        while die:
            menu_choice = st.radio(
                "Please Select the mode of operation:",
                [
                    "Give Input",
                    "Initiate Key Generation Process",
                    "Initiate RSA Encryption For Assymetric Common Key sharing",
                    "Initiate Symmetric Encryption for conversation after key sharing",
                    "Decrypt Asymmetrically shared common key",
                    "Decrypt message sent through Symmetric Conversation",
                    "Exit the program",
                ]
            )

            if menu_choice == "Give Input":
                st.write("##### DATA INPUT #####")
                p, q, common_key = Input_data()
                time.sleep(2)
            elif menu_choice == "Initiate Key Generation Process":
                st.write("##### KEY GENERATION PROCESS #####")
                n, e, d = RSAKeyGeneration(p, q)
                time.sleep(1)
            elif menu_choice == "Initiate RSA Encryption For Assymetric Common Key sharing":
                st.write("##### RSA ENCRYPTION PROCESS #####")
                cipher = RSAEncryption(e, n, common_key)
                time.sleep(1)
            elif menu_choice == "Initiate Symmetric Encryption for conversation after key sharing":
                st.write("##### SYMMETRIC ENCRYPTION PROCESS #####")
                hashed_msz, encoded_msz = SymmetricEncryption(common_key)
                time.sleep(1)
            elif menu_choice == "Decrypt Asymmetrically shared common key":
                st.write("##### RSA DECRYPTION PROCESS #####")
                decipher = RSADecryption(n, d, cipher, common_key)
                time.sleep(1)
            elif menu_choice == "Decrypt message sent through Symmetric Conversation":
                st.write("##### SYMMETRIC DECRYPTION PROCESS #####")
                SymmetricDecryption(hashed_msz, encoded_msz, decipher)
                time.sleep(1)
            elif menu_choice == "Exit the program":
                die = False
                st.write("Exiting the program...")
            else:
                st.write("Please select a valid option from the menu.")
    except KeyboardInterrupt:
        st.write("\n\nInterrupt received! Exiting cleanly...\n")

if __name__ == '__main__':
    main()
