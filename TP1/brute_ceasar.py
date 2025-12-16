# -*- coding: utf-8 -*-
from Ceasar_Encryption import caesar_decrypt


def brute_force_caesar(ciphertext: str) -> list[tuple[int, str]]:
    """Try all 26 possible shifts and return results."""
    results = []
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        results.append((shift, decrypted))
    return results


if __name__ == "__main__":
    encrypted = "ERQMRXU!"

    print(f"Texte chiffre: {encrypted}\n")
    print("Brute force - tous les d�calages possibles:")
    print("-" * 40)

    for shift, decrypted in brute_force_caesar(encrypted):
        print(f"Shift {shift:2d}: {decrypted}")
