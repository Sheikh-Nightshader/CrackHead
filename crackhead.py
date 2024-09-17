import hashlib
import base64
import argparse
from colorama import Fore, Style, init

init(autoreset=True)

def hash_password(password, algorithm='md5'):
    if algorithm == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(password.encode()).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == 'sha512':
        return hashlib.sha512(password.encode()).hexdigest()
    elif algorithm == 'base64':
        return base64.b64encode(password.encode()).decode()
    else:
        raise ValueError("Unsupported hashing or encoding algorithm")

def crack_hash(target_hash, algorithm, dictionary_file):
    try:
        with open(dictionary_file, 'r') as file:
            for password in file:
                password = password.strip()
                hashed_password = hash_password(password, algorithm)
                if hashed_password == target_hash:
                    return password
    except FileNotFoundError:
        print(f"{Fore.RED}Dictionary file not found.")
        return None
    return None

def print_banner():
    banner = f"""
{Fore.CYAN}#####################################################
#                                                   #
# {Fore.GREEN}   Sheikh Nightshader's Crackhead Tool          {Fore.CYAN}#
# {Fore.YELLOW}  Crack MD5, SHA1, SHA256, SHA512, and Base64    {Fore.CYAN}#
# {Fore.MAGENTA}       Password Cracker & Encoder/Decoder        {Fore.CYAN}#
#                                                   #
#####################################################
"""
    print(banner)

def main():
    parser = argparse.ArgumentParser(description='Crack hashed passwords using a dictionary attack.')
    parser.add_argument('target_hash', type=str, help='The hash to crack')
    parser.add_argument('algorithm', type=str, choices=['md5', 'sha1', 'sha256', 'sha512', 'base64'], help='Hashing algorithm used')
    parser.add_argument('dictionary_file', type=str, help='Path to the dictionary file')

    args = parser.parse_args()

    print_banner()

    cracked_password = crack_hash(args.target_hash, args.algorithm, args.dictionary_file)
    if cracked_password:
        print(f"{Fore.GREEN}Password found: {cracked_password}")
    else:
        print(f"{Fore.RED}Password not found")

if __name__ == "__main__":
    main()
