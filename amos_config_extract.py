# Author: RussianPanda
# Tested on samples : 0d8633fa3134bdfde66f7f501313c4e1

import binascii
import base64
import re
import sys

def find_alphabet_and_data(binary_data):

    alphabet_pattern = rb"(?=[\x21-\x7E]{64})([\x21-\x7E]{64})"
    match = re.search(alphabet_pattern, binary_data)
    if not match:
        raise ValueError("Custom Base64 alphabet not found in the binary data.")
    
    custom_alphabet = match.group(0).decode()

    encoded_data_start = match.end() + 1  # Skip the null byte

    null_byte_index = binary_data.find(b'\x00', encoded_data_start)
    if null_byte_index == -1:
        raise ValueError("Null byte not found after the encoded data.")

    encoded_hex_string = binary_data[encoded_data_start:null_byte_index].decode()
    
    return custom_alphabet, encoded_hex_string

def add_base64_padding(data):
    return data + '=' * (-len(data) % 4)

def dec_b64(encoded_data, custom_alphabet):
    standard_b64_alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    translation_table = bytes.maketrans(custom_alphabet.encode(), standard_b64_alphabet)

    standard_b64_data = encoded_data.translate(translation_table)

    padded_data = add_base64_padding(standard_b64_data)

    return base64.b64decode(padded_data)

def extract_val_from_config(decoded_data):
    user_match = re.search(r'user:\s*([^\s"]+)', decoded_data)
    buildid_match = re.search(r'BuildID:\s*([^\s"]+)', decoded_data)
    url_match = re.search(r'(https?://[^\s"]+)', decoded_data)
    
    user = user_match.group(1).rstrip("\\") if user_match else "Not Found"
    buildid = buildid_match.group(1).rstrip("\\") if buildid_match else "Not Found"
    url = url_match.group(1).rstrip("\\") if url_match else "Not Found"
    
    return user, buildid, url

def main():
    if len(sys.argv) < 2:
        print("Usage: python amos_config_extract.py <binary_file_path>")
        sys.exit(1)
    
    binary_file_path = sys.argv[1]

    try:
        with open(binary_file_path, "rb") as file:
            binary_data = file.read()
    except FileNotFoundError:
        print(f"File not found: {binary_file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    try:
        custom_alphabet, encoded_hex_string = find_alphabet_and_data(binary_data)
    except ValueError as e:
        print(str(e))
        sys.exit(1)

    try:
        enc_data = binascii.unhexlify(encoded_hex_string)

        encoded_data = enc_data.decode(errors="ignore")

        decoded_data = dec_b64(encoded_data, custom_alphabet).decode(errors="replace")
        #print("Decoded data:", decoded_data)
        
        user, buildid, url = extract_val_from_config(decoded_data)
        print(f"User: {user}")
        print(f"Build ID: {buildid}")
        print(f"C2: {url}")
    except Exception as e:
        print(f"Error during decoding: {e}")

if __name__ == "__main__":
    main()
