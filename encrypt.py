#!/usr/bin/env python3
import boto3
import base64
from base_kms import new_kms_client
from cryptography.fernet import Fernet

NUM_BYTES_FOR_LEN = 4



def create_data_key(kms_client, cmk_id, key_spec="AES_256"):
    """Generate a data key to use when encrypting and decrypting data"""

    # Create data key
    response = kms_client.generate_data_key(KeyId=cmk_id, KeySpec=key_spec)

    # Return the encrypted and plaintext data key
    return response["CiphertextBlob"], base64.b64encode(response["Plaintext"])


def encrypt_file(kms_client, filename, cmk_id):

    # Read the entire file into memory
    try:
        with open(filename, 'rb') as file:
            file_contents = file.read()
    except IOError as e:
        return False


    # Generate a data key associated with the CMK
    # The data key is used to encrypt the file. Each file can use its own
    # data key or data keys can be shared among files.
    # Specify either the CMK ID or ARN
    data_key_encrypted, data_key_plaintext = create_data_key(kms_client, cmk_id)
    if data_key_encrypted is None:
        return False

    # Encrypt the file
    f = Fernet(data_key_plaintext)
    file_contents_encrypted = f.encrypt(file_contents)

    # Write the encrypted data key and encrypted file contents together
    try:
        with open(filename + '.encrypted', 'wb') as file_encrypted:
            file_encrypted.write(len(data_key_encrypted).to_bytes(NUM_BYTES_FOR_LEN,
                                                                  byteorder='big'))
            file_encrypted.write(data_key_encrypted)
            file_encrypted.write(file_contents_encrypted)
    except IOError as e:
        return False

    # For the highest security, the data_key_plaintext value should be wiped
    # from memory. Unfortunately, this is not possible in Python. However,
    # storing the value in a local variable makes it available for garbage
    # collection.
    return True


if __name__ == '__main__':
    profile_name = input('Please enter the profile you want to use: ')
    kms_client = new_kms_client(profile_name)

    filename = 'test.txt'
    cmk_id = 'alias/test'

    enc = encrypt_file(kms_client, filename, cmk_id)
    if enc:
        print("File was encrypted")