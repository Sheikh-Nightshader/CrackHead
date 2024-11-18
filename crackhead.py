import hashlib
import threading
import itertools


def print_banner():
    print("\033[1;32m")
    print(r"""
 ____                 _    _   _                _
| ___|_ __ __ _  ___ | | _| | | | ___  __ _  __| |
| |   | '__/ _` |/ __| |/ / |_| |/ _ \/ _` |/ _` |
| |___| | | (_| | (__|   <|  _  |  __/ (_| | (_| |
 \____|_|  \__,_|\___|_|\_\_| |_|\___|\__,_|\__,_|

          v2 by Sheikh Nightshader
    """)
    print("\033[0m")


def crack_hash(hash_type, hash_value, wordlist=None, brute_force=False):
    def brute_force_attack():
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=<>?/"
        found = False
        attempts = 0
        for length in range(1, 25):
            if found:
                break
            for candidate in itertools.product(chars, repeat=length):
                guess = ''.join(candidate)
                if hash_type == "md5":
                    guess_hash = hashlib.md5(guess.encode()).hexdigest()
                elif hash_type == "sha1":
                    guess_hash = hashlib.sha1(guess.encode()).hexdigest()
                elif hash_type == "sha256":
                    guess_hash = hashlib.sha256(guess.encode()).hexdigest()
                elif hash_type == "sha512":
                    guess_hash = hashlib.sha512(guess.encode()).hexdigest()
                elif hash_type == "mysql":
                    guess_hash = hashlib.md5(guess.encode()).hexdigest()

                if hash_value == guess_hash:
                    found = True
                    print(f"\033[1;34m[+] Found: {guess}\033[0m")
                    return
                attempts += 1
                if attempts % 1000 == 0:
                    print(f"\033[1;36m[-] Trying: {guess} ({attempts} attempts)\033[0m", end='\r')

        if not found:
            print("\033[1;31m[!] Password not found after trying all combinations.\033[0m")

    def dictionary_attack():
        found = False
        try:
            with open(wordlist, 'r') as file:
                for line in file:
                    guess = line.strip()
                    if hash_type == "md5":
                        guess_hash = hashlib.md5(guess.encode()).hexdigest()
                    elif hash_type == "sha1":
                        guess_hash = hashlib.sha1(guess.encode()).hexdigest()
                    elif hash_type == "sha256":
                        guess_hash = hashlib.sha256(guess.encode()).hexdigest()
                    elif hash_type == "sha512":
                        guess_hash = hashlib.sha512(guess.encode()).hexdigest()
                    elif hash_type == "mysql":
                        guess_hash = hashlib.md5(guess.encode()).hexdigest()


                    if hash_value == guess_hash:
                        found = True
                        print(f"\033[1;34m[+] Found: {guess}\033[0m")
                        break


            if not found:
                print("\033[1;31m[!] Password not found.\033[0m")
        except FileNotFoundError:
            print(f"\033[1;31m[!] Wordlist file not found: {wordlist}\033[0m")

    if brute_force:
        print("\033[1;33m[*] Starting brute-force attack...\033[0m")
        brute_force_attack()
    elif wordlist:
        print("\033[1;33m[*] Starting dictionary attack...\033[0m")
        dictionary_attack()
    else:
        print("\033[1;31m[!] No method specified!\033[0m")


def threaded_attack(hash_type, hash_value, wordlist, brute_force):
    thread = threading.Thread(target=crack_hash, args=(hash_type, hash_value, wordlist, brute_force))
    thread.start()


def main():
    print_banner()
    hash_type = input("\033[1;33mEnter hash type (md5, sha1, sha256, sha512, mysql): \033[0m").lower()
    hash_value = input("\033[1;33mEnter the hash to crack: \033[0m")
    attack_type = input("\033[1;33mChoose attack type (dict/brute): \033[0m").lower()

    if attack_type == 'dict':
        wordlist = input("\033[1;33mEnter path to wordlist: \033[0m")
        threaded_attack(hash_type, hash_value, wordlist, False)
    elif attack_type == 'brute':
        threaded_attack(hash_type, hash_value, None, True)
    else:
        print("\033[1;31m[!] Invalid attack type.\033[0m")

if __name__ == "__main__":
    main()
