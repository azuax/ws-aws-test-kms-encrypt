#!/usr/bin/env python3
import boto3
import base64
import json

from base_kms import new_kms_client
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet


def decrypt_data_key(kms_client, data_key_encrypted):
    """
    Decrypts an encrypted data key.
    """

    # Decrypt the data key
    try:
        response = kms_client.decrypt(CiphertextBlob=data_key_encrypted)
    except ClientError as e:
        return None

    # Return plaintext base64-encoded binary data key
    return base64.b64encode((response['Plaintext']))


def decrypt_file(kms_client, filename, num_bytes_for_len):
    """
    Decrypts a file encrypted by encrypt_file() by using a KMS key.
    """
    # Read the encrypted file into memory
    try:
        with open(filename, 'rb') as file:
            file_contents = file.read()
    except IOError as e:
        return False

    data_key_encrypted_len = int.from_bytes(file_contents[:num_bytes_for_len],
                                            byteorder='big') \
                             + num_bytes_for_len
    data_key_encrypted = file_contents[
        num_bytes_for_len:data_key_encrypted_len]

    # Decrypt the data key before using it
    data_key_plaintext = decrypt_data_key(kms_client, data_key_encrypted)
    if data_key_plaintext is None:
        return False

    # Decrypt the rest of the file
    f = Fernet(data_key_plaintext)
    file_contents_decrypted = f.decrypt(file_contents[data_key_encrypted_len:])

    # Write the decrypted file contents
    try:
        with open(filename + '.decrypted', 'wb') as file_decrypted:
            file_decrypted.write(file_contents_decrypted)
    except IOError as e:
        return False
    except ClientError:
        raise
    else:
        return True

if __name__ == '__main__':
    NUM_BYTES_FOR_LEN = 4
    profile_name = 'azuax-dl'
    kms_client = new_kms_client(profile_name)

    filename = 'test.txt.encrypted'

    dec = decrypt_file(kms_client, filename, NUM_BYTES_FOR_LEN)

    if dec:
        print("The file was decrypted")