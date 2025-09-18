import string
from collections import Counter  # For counting letter frequencies

# Define the alphabet for letter-to-index mapping
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Small set of common English words for scoring candidate plaintexts
common_words = ["THE", "AND", "OF", "TO", "IN", "A", "IS", "FOR", "WITH", "ON", "BY", "AS"]

# Function to calculate the Index of Coincidence for a text
def index_of_coincidence(text):
    N = len(text)
    freqs = Counter(text)  # Count frequency of each letter
    ic = sum(f * (f - 1) for f in freqs.values()) / (N * (N - 1)) if N > 1 else 0
    return ic  # Returns the likelihood that two letters are the same

# Estimate the keyword length by comparing IC of multiple splits
def find_key_length(ciphertext, min_len=2, max_len=12):
    best_len, best_diff = 0, 1e9  # Initialize best key length and IC difference
    for k in range(min_len, max_len + 1):
        # Split the ciphertext into k substreams
        streams = [''.join(ciphertext[i] for i in range(len(ciphertext)) if i % k == j) for j in range(k)]
        avg_ic = sum(index_of_coincidence(s) for s in streams if len(s) > 1) / k  # Average IC across streams
        diff = abs(avg_ic - 0.065)  # Difference from expected English IC
        if diff < best_diff:  # Keep the key length with IC closest to English
            best_len, best_diff = k, diff
    return best_len  # Return estimated keyword length

# Shift a single letter backwards by 'shift' positions
def shift_letter(letter, shift):
    return alphabet[(alphabet.index(letter) - shift) % 26]

# Decrypt a ciphertext given a keyword
def decrypt_with_keyword(ciphertext, keyword):
    plaintext = ""
    j = 0  # Index in keyword
    for char in ciphertext:
        if char in alphabet:
            c = alphabet.index(char)  # Ciphertext letter index
            k = alphabet.index(keyword[j % len(keyword)])  # Keyword letter index
            p = (c - k + len(alphabet)) % 26  # Decrypt using modulo 26
            plaintext += alphabet[p]
            j += 1
        else:
            plaintext += char  # Non-letters copied directly
    return plaintext

# Simple scoring function based on frequency of common English words
def score_plaintext(text):
    score = 0
    for word in common_words:
        score += text.count(word)  # Count occurrences of each common word
    return score

# Estimate the keyword by analyzing each substream (Caesar shift)
def find_keyword(ciphertext, key_len):
    keyword = ""
    english_common = "ETAOIN"  # Most frequent letters in English
    for j in range(key_len):
        stream = ''.join(ciphertext[i] for i in range(len(ciphertext)) if i % key_len == j)
        freqs = Counter(stream)
        most_common_letter = freqs.most_common(1)[0][0]  # Most frequent letter in stream
        best_shift, best_score = 0, -1
        # Try mapping most common letter to each frequent English letter
        for ref in english_common:
            shift = (alphabet.index(most_common_letter) - alphabet.index(ref)) % 26
            decrypted_stream = ''.join(shift_letter(c, shift) for c in stream)
            score = sum(decrypted_stream.count(ch) for ch in english_common)
            if score > best_score:
                best_score, best_shift = score, shift  # Keep best scoring shift
        keyword += alphabet[best_shift]  # Add estimated letter to keyword
    return keyword

# Main execution
if __name__ == "__main__":
    # Read ciphertext and remove non-letter characters
    with open("cipherNoKey.txt", "r") as f:
        ciphertext = ''.join(ch for ch in f.read().upper() if ch in alphabet)

    # Step 1: estimate key length
    key_len = find_key_length(ciphertext)
    print("Estimated key length:", key_len)

    # Step 2: estimate keyword
    keyword = find_keyword(ciphertext, key_len)
    print("Estimated keyword before refinement:", keyword)

    # Step 3: initial decryption with estimated keyword
    plaintext = decrypt_with_keyword(ciphertext, keyword)

    # Step 4: refine keyword by rotating it to maximize English word matches
    best_plaintext = plaintext
    best_keyword = keyword
    best_score = score_plaintext(plaintext)
    for i in range(key_len):
        rotated_keyword = keyword[i:] + keyword[:i]  # Rotate keyword
        candidate = decrypt_with_keyword(ciphertext, rotated_keyword)
        candidate_score = score_plaintext(candidate)
        if candidate_score > best_score:  # Keep candidate if better English score
            best_score = candidate_score
            best_plaintext = candidate
            best_keyword = rotated_keyword

    print("Refined keyword:", best_keyword)
    print("English word score:", best_score)

    # Save final plaintext to file
    with open("plainNoKey.txt", "w") as f:
        f.write(best_plaintext)

    print("Decryption complete. Saved to plainNoKey.txt")
