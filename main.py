from google.cloud import kms_v1
import hashlib

def list_keys(project_id, location_id, key_ring_id, crypto_key_id):
    client = kms_v1.KeyManagementServiceClient()
    crypto_key_name = client.crypto_key_path(project_id, location_id, key_ring_id, crypto_key_id)
    key_versions = client.list_crypto_key_versions(parent=crypto_key_name)
    for version in key_versions:
        print(f"Version ID: {version.name.split('/')[-1]}")
        print(f"Create Time: {version.create_time}")
        print(f"State: {version.state}")
        print(version.algorithm)
        print("")



def symetric_encrypt(project_id, location_id, key_ring_id, crypto_key_id, plaintext):
    client = kms_v1.KeyManagementServiceClient()
    crypto_key_name = client.crypto_key_path(project_id, location_id, key_ring_id, crypto_key_id)
    plaintext_bytes = plaintext.encode("utf-8")
    response = client.encrypt(
        name=crypto_key_name,
        plaintext=plaintext_bytes,
    )
    ciphertext = response.ciphertext
    return ciphertext



def symetric_decrypt(project_id, location_id, key_ring_id, crypto_key_id, ciphertext):
    client = kms_v1.KeyManagementServiceClient()
    crypto_key_name = client.crypto_key_path(project_id, location_id, key_ring_id, crypto_key_id)
    if isinstance(ciphertext, str):
        ciphertext = bytes.fromhex(ciphertext)
    response = client.decrypt(
        name=crypto_key_name,
        ciphertext=ciphertext,
    )
    decrypted_plaintext = response.plaintext.decode("utf-8")
    return decrypted_plaintext


def asymmetric(project_id, location_id, key_ring_id, crypto_key_id, key_version_id, message):
    client = kms_v1.KeyManagementServiceClient()
    key_version_name = client.crypto_key_version_path(project_id, location_id, key_ring_id, crypto_key_id, key_version_id)
    message_bytes = message.encode('utf-8')
    hash_ = hashlib.sha256(message_bytes).digest()
    sign_response = client.asymmetric_sign(
        name=key_version_name,
        digest={'sha256': hash_}
    )
    signature = sign_response.signature
    print(signature)

    public_path = client.public_key_path(
        project = project_id,
        location = location_id,
        key_ring=key_ring_id,
        crypto_key=crypto_key_id,
        crypto_key_version=key_version_id,
    )
    print(public_path)





# vars symetric
project_id = "festive-utility-407111"
location_id = "global"
key_ring_id = "python"
crypto_key_id = "python-asymetric-sign"
key_version_id = "1"


plaintext = "Hello, GCP KMS!"

try:
    asymmetric(project_id, location_id, key_ring_id, crypto_key_id, key_version_id , plaintext)
    # list_keys(project_id, location_id, key_ring_id, crypto_key_id)

    # print(symetric_encrypt(project_id, location_id, key_ring_id, crypto_key_id, plaintext))

    # ciphertext = symetric_encrypt(project_id, location_id, key_ring_id, crypto_key_id, plaintext)
    # print(symetric_decrypt(project_id, location_id, key_ring_id, crypto_key_id, ciphertext))


except Exception as e:
    print(f"Error: {e}")
