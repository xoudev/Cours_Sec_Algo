def caesar_encrypt(plaintext: str, shift: int) -> str:
    """Encrypt plaintext using Caesar cipher with given shift."""
    result = []
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - base + shift) % 26 + base
            result.append(chr(shifted))
        else:
            result.append(char)
    return ''.join(result)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Decrypt ciphertext using Caesar cipher with given shift."""
    return caesar_encrypt(ciphertext, -shift)


if __name__ == "__main__":
    text = "Hello, World!"
    shift = 3

    encrypted = caesar_encrypt(text, shift)
    decrypted = caesar_decrypt(encrypted, shift)

    print(f"Original:  {text}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
