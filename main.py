import bcrypt
import base64
import nltk
import time

# Read shadow file
def read_shadow_file(file_path):
    shadow_data = []
    # CHANGE THIS FOR WORKFACTOR CHANGES:
    work_val = 8
    # ---------------------------------
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.strip().split(':')
            username, algorithm_workfactor_salt_hash = parts[0], parts[1]
            new_parts = algorithm_workfactor_salt_hash.split("$")
            algorithm, workfactor, salt_hash = new_parts[1], new_parts[2], new_parts[3]
            #print(username, algorithm, workfactor, salt_hash, algorithm_workfactor_salt_hash)
            salt, hashed_password = salt_hash[:22], salt_hash[22:]
            #print(hashed_password)
            if(int(workfactor) == work_val):
                shadow_data.append((username, algorithm, int(workfactor), salt, hashed_password, algorithm_workfactor_salt_hash))
    return shadow_data

def generate_passwords():
    nltk.download('words')
    word_corpus = nltk.corpus.words.words()
    potential_passwords = []
    for word in word_corpus:
        if 6 <= len(word) <= 10:
            potential_passwords.append(word)
    return potential_passwords

def crack_passwords(shadow_data, potential_passwords):
    cracked_passwords = {}
    start_time = time.time()
    curr_ascii = 96
    for username, algorithm, workfactor, salt, hashed_password, alg_wf_sh in shadow_data:
        for password in potential_passwords:
            ascii = ord(password[0])
            if(ascii != curr_ascii and abs(ascii-curr_ascii) != 32):
                curr_ascii = ascii
                print("new char: ", ord(password[0]), "\n")
            # Hash password with given salt and work factor???
            updated_salt = f"${algorithm}${workfactor}${salt}"
            hashed_attempt = bcrypt.hashpw(password.encode(), updated_salt.encode())
            # Compare hashed attempt with hashed password from shadow file??
            if hashed_attempt == alg_wf_sh.encode():
                print(f"found a pass: {password}!")
                cracked_passwords[username] = password
                break
    end_time = time.time()
    time_taken = end_time - start_time
    return cracked_passwords, time_taken

def main():
    shadow_file_path = 'shadow.txt'
    shadow_data = read_shadow_file(shadow_file_path)
    potential_passwords = generate_passwords()
    cracked_passwords, time_taken = crack_passwords(shadow_data, potential_passwords)
    print("Cracked passwords:")
    for username, password in cracked_passwords.items():
        print(f"Username: {username}, Password: {password}")
    print(f"Time taken: {time_taken} seconds")

if __name__ == "__main__":
    main()
