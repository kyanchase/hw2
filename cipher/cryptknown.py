# Define the alphabet we'll use for encryption/decryption
# Each letter's index corresponds to its shift value (A=0, B=1, ..., Z=25)
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Function to encrypt plaintext using the Vigenère cipher
def vigenere_encrypt(plaintext, keyword):
    ciphertext = ""  # Initialize empty string to store the ciphertext
    keyword = keyword.upper()  # Ensure the keyword is in uppercase
    j = 0  # Index for the keyword
    for char in plaintext.upper():  # Loop through each character in plaintext
        if char in alphabet:  # Only encrypt letters, skip others (spaces, punctuation)
            p = alphabet.index(char)  # Get numeric index of plaintext letter
            k = alphabet.index(keyword[j % len(keyword)])  # Get corresponding key letter index
            c = alphabet[(p + k) % len(alphabet)]  # Encrypt using (p + k) mod 26
            ciphertext += c  # Append encrypted letter to ciphertext
            j += 1  # Move to next keyword letter
        else:
            ciphertext += char  # Non-alphabet characters are copied directly
    return ciphertext  # Return the final encrypted string

# Function to decrypt ciphertext using the Vigenère cipher
def vigenere_decrypt(ciphertext, keyword):
    plaintext = ""  # Initialize empty string for plaintext
    keyword = keyword.upper()  # Ensure keyword is uppercase
    j = 0  # Index for the keyword
    for char in ciphertext.upper():  # Loop through each character
        if char in alphabet:  # Only process letters
            c = alphabet.index(char)  # Numeric index of ciphertext letter
            k = alphabet.index(keyword[j % len(keyword)])  # Corresponding keyword letter
            p = (c - k + len(alphabet)) % len(alphabet)  # Decrypt: (c - k) mod 26
            plaintext += alphabet[p]  # Append decrypted letter to plaintext
            j += 1  # Move to next keyword letter
        else:
            plaintext += char  # Non-letter characters copied as-is
    return plaintext  # Return decrypted string

# Main block to execute when running this file directly
if __name__ == "__main__":
    keyword = "TAGORE"  # Known keyword for decryption

    # Read the ciphertext from a file
    with open("cipherKnownKey.txt", "r") as f:
        ciphertext = f.read()

    # Use the decryption function to recover the plaintext
    plaintext = vigenere_decrypt(ciphertext, keyword)

    # Save the decrypted plaintext to a new file
    with open("plainKnownKey.txt", "w") as f:
        f.write(plaintext)

    # Print a message to indicate success
    print("Decryption complete. Saved to plainKnownKey.txt")
