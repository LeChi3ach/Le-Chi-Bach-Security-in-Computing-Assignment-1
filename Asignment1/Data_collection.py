# This code was done with with the instruction of AI model Gemini
# "How to perform [Cryptographic algorithm] in python?", Gemini, Google, Nov 2026, google.com.

import os
import hashlib
import time
import secrets
import pandas as pd
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, dh
from cryptography.hazmat.primitives import hashes, keywrap
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

data_size = {
    "1_KB": os.urandom(1024),
    "100_KB": os.urandom(1024 * 100),
    "1_MB": os.urandom(1024 * 1024)
}

symmetric_key = os.urandom(32) #256 bit key for AES, ChaCha20
triple_des_key = os.urandom(24) #192 bit for 3des
iv = os.urandom(16) #IV for AES, 3des
nonce = os.urandom(16) #nonce for ChaCha20

rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_public_key = rsa_private_key.public_key()

ecdh_sender_private = ec.generate_private_key(ec.SECP256R1())
ecdh_receiver_private = ec.generate_private_key(ec.SECP256R1())
ecdh_receiver_public = ecdh_receiver_private.public_key()

elgamal_params = dh.generate_parameters(generator=2, key_size=2048).parameter_numbers()
p_elgamal = elgamal_params.p
g_elgamal = elgamal_params.g
elgamal_private = secrets.randbelow(p_elgamal - 2) + 1
elgamal_public = pow(g_elgamal, elgamal_private, p_elgamal )


collected_data = []
NUM_REPEATS = 30

for size, data in data_size.items():
    for run_id in range (1, NUM_REPEATS +1):
        #-----hashing algorithms-----
        #MD5
        t_start = time.perf_counter_ns()
        md5_output = len(hashlib.md5(data).hexdigest())
        collected_data.append([run_id, "Hashing", "MD5", size, md5_output, time.perf_counter_ns() - t_start])

        #SHA-256
        t_start = time.perf_counter_ns()
        sha2_output = len(hashlib.sha256(data).hexdigest())
        collected_data.append([run_id, "Hashing", "SHA-256", size, sha2_output, time.perf_counter_ns() - t_start])

        #SHA3-256
        t_start = time.perf_counter_ns()
        sha3_output = len(hashlib.sha3_256(data).hexdigest())
        collected_data.append([run_id, "Hashing", "SHA3-256", size, sha3_output, time.perf_counter_ns() - t_start])

        #------Symmetric cryptography------
        #AES-CBC
        cipher_aes = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
        encryptor_aes = cipher_aes.encryptor()
        padding_length = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_length] * padding_length)

        t_start = time.perf_counter_ns()
        aes_length = len(encryptor_aes.update(padded_data) + encryptor_aes.finalize())
        collected_data.append([run_id, "Symmetric", "AES", size, aes_length, time.perf_counter_ns() - t_start])

        #ChaCha20
        cipher_chacha = Cipher(algorithms.ChaCha20(symmetric_key, nonce), mode=None)
        encryptor_chacha = cipher_chacha.encryptor()
        t_start = time.perf_counter_ns()
        chacha_length = len(encryptor_chacha.update(data) + encryptor_chacha.finalize())
        collected_data.append([run_id, "Symmetric", "ChaCha20", size, chacha_length, time.perf_counter_ns() - t_start])

        #3Des
        cipher_3des = Cipher(algorithms.TripleDES(triple_des_key), modes.CBC(iv[:8]))
        encryptor_3des = cipher_3des.encryptor()
        padding_length_3des = 8 - (len(data) % 8)
        padding_data_3des = data + bytes([padding_length_3des] * padding_length_3des)
        t_start = time.perf_counter_ns()
        IIIdes_length = len(encryptor_3des.update(padding_data_3des) + encryptor_3des.finalize())
        collected_data.append([run_id, "Symmetric", "3DES", size, IIIdes_length, time.perf_counter_ns() - t_start])

        #------Asymmetric Cryptography------
        #RSA
        t_start = time.perf_counter_ns()
        session_key_rsa = os.urandom(32)
        enc_rsa = Cipher(algorithms.AES(session_key_rsa), modes.CBC(iv)).encryptor()
        rsa_body = enc_rsa.update(padded_data) + enc_rsa.finalize()
        enc_session_key_rsa = rsa_public_key.encrypt(session_key_rsa, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        rsa_length = len(enc_session_key_rsa) + len(rsa_body)
        collected_data.append([run_id, "Asymmetric", "RSA", size, rsa_length, time.perf_counter_ns() - t_start])

        #ECDH
        t_start = time.perf_counter_ns()
        session_key_ecdh = os.urandom(32)
        shared_secret_ecdh = ecdh_sender_private.exchange(ec.ECDH(), ecdh_receiver_public)
        key_ecdh = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ecdh").derive(shared_secret_ecdh)
        wrapped_key_ecdh = keywrap.aes_key_wrap(key_ecdh, session_key_ecdh)
        enc_ecdh = Cipher(algorithms.AES(session_key_ecdh), modes.CBC(iv)).encryptor()
        ecdh_body = enc_ecdh.update(padded_data) + enc_ecdh.finalize()
        ecdh_length = len(wrapped_key_ecdh) + len(ecdh_body)
        collected_data.append([run_id, "Asymmetric", "ECDH", size, ecdh_length, time.perf_counter_ns() - t_start])

        #ElGamal
        t_start = time.perf_counter_ns()
        session_key_elgamal = os.urandom(32)
        m_int = int.from_bytes(session_key_elgamal, byteorder="big")
        k_ephemeral = secrets.randbelow(p_elgamal - 2) + 1
        c1 = pow(g_elgamal, k_ephemeral, p_elgamal)
        c2 = (m_int * pow(elgamal_public, k_ephemeral, p_elgamal)) % p_elgamal
        c1_bytes = c1.to_bytes(256, byteorder="big")
        c2_bytes = c2.to_bytes(256, byteorder="big")
        enc_elgamal = Cipher(algorithms.AES(session_key_elgamal), modes.CBC(iv)).encryptor()
        elgamal_body = enc_elgamal.update(padded_data) + enc_elgamal.finalize()
        total_len_elgamal = len(c1_bytes) + len(c2_bytes) + len(elgamal_body)
        collected_data.append([run_id, "Asymmetric", "ElGamal", size, total_len_elgamal, time.perf_counter_ns() - t_start])

df = pd.DataFrame(collected_data, columns=["Run_ID", "Group", "Algorithm", "Input_Size", "Output_Length", "Execution_Time"])

output_filename = "crypto_performace_data.csv"
df.to_csv(output_filename, index=False)

excel_filename = "ANOVA_1MB.xlsx"
df_1mb = df[df["Input_Size"] == "1_MB"]
pivot_time = df_1mb.pivot(index="Run_ID", columns="Algorithm", values="Execution_Time")
pivot_time.to_excel(excel_filename, index=False)


print(f"data saved at {os.path.abspath(output_filename)}")
