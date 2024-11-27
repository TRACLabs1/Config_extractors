import pefile
import re
import sys
import hashlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_32


def is_print_ascii(byte):
    return 0x20 <= byte <= 0x7E


def read_fixed_length(pe, address, length):
    rva = address - pe.OPTIONAL_HEADER.ImageBase
    memory_image = pe.get_memory_mapped_image()

    if rva >= len(memory_image):
        return None, None

    data = memory_image[rva : rva + length]
    return data, data.hex()


def read_until_next_str(pe, address):
    rva = address - pe.OPTIONAL_HEADER.ImageBase
    memory_image = pe.get_memory_mapped_image()

    if rva >= len(memory_image):
        return None, None

    extracted = bytearray()
    for offset in range(rva, len(memory_image)):
        byte = memory_image[offset]

        if is_print_ascii(byte):
            extracted.append(byte)
        elif byte == 0x00:
            break
        else:
            break  

    return extracted, extracted.hex()


def xor_decrypt(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])


def extract_url_and_build_id(decrypted_blob):
    strings = [line.strip() for line in decrypted_blob.splitlines() if line.strip()]
    full_url = None
    dll_dependencies_url = None
    build_id = None

    url_pattern = re.compile(r"http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    for i, string in enumerate(strings):
        if url_pattern.match(string):  # Valid URL found
            base_url = string
            if i + 2 < len(strings):
                full_url = f"{base_url}{strings[i + 2]}"

            if i + 3 < len(strings):
                dll_dependencies_url = f"{base_url}{strings[i + 3]}"

            if i + 4 < len(strings):
                build_id = strings[i + 4]
            break

    return full_url, dll_dependencies_url, build_id


def compute_file_hashes(file_path):
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
            md5_hash = hashlib.md5(file_data).hexdigest()
            sha1_hash = hashlib.sha1(file_data).hexdigest()
            sha256_hash = hashlib.sha256(file_data).hexdigest()

        return md5_hash, sha1_hash, sha256_hash
    except Exception as e:
        print(f"Failed to compute hashes: {e}")
        return None, None, None


def analyze_pe_file(file_path):
    try:
        pe = pefile.PE(file_path)
        memory_image = pe.get_memory_mapped_image()
        image_base = pe.OPTIONAL_HEADER.ImageBase
        pattern = re.compile(rb"\x68(..C)\x00\x68(..C)\x00")
        matches = list(pattern.finditer(memory_image))

        if not matches:
            print("No matches found.")
            return

        md = Cs(CS_ARCH_X86, CS_MODE_32)
        decrypted_blob = "" 

        for i, match in enumerate(matches):
            start = match.start()
            disassembled = list(md.disasm(memory_image[start:], image_base + start))
            push_addr = []
            for j, ins in enumerate(disassembled[:5]): 
                if ins.mnemonic == "push":
                    try:
                        push_value = int(ins.op_str, 16)
                        push_addr.append(push_value)
                    except ValueError:
                        continue

            if len(push_addr) >= 2:
                addr1 = push_addr[0]
                addr2 = push_addr[1]

                data1, _ = read_until_next_str(pe, addr1)
                if not data1:
                    print(f"Unable to read data at address {hex(addr1)}.")
                    continue

                length = len(data1)
                data2, _ = read_fixed_length(pe, addr2, length)
                if not data2:
                    print(f"Unable to read data at address {hex(addr2)}.")
                    continue

                decrypted_data = xor_decrypt(data1, data2)
                decrypted_blob += decrypted_data.decode("ascii", errors="ignore") + "\n"

        full_url, dll_dependencies_url, build_id = extract_url_and_build_id(decrypted_blob)
        if full_url:
            print(f"C2: {full_url}")
        if dll_dependencies_url:
            print(f"DLL Dependencies URL: {dll_dependencies_url}")
        if build_id:
            print(f"Build ID: {build_id}")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python stealc_config_extractor.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    md5, sha1, sha256 = compute_file_hashes(file_path)

    print(f"MD5: {md5}")
    print(f"SHA1: {sha1}")
    print(f"SHA256: {sha256}")

    analyze_pe_file(file_path)
