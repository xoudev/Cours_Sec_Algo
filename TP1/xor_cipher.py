"""
Algorithme de chiffrement XOR
Simple et symétrique : même fonction pour chiffrer et déchiffrer
Sans dépendance externe
"""

CLE = "MaSuperCleSecrete123"


def xor_chiffrer(texte, cle):
    """
    Chiffre un texte avec XOR et retourne le résultat en hexadécimal
    """
    resultat = ""
    for i, c in enumerate(texte):
        xor_val = ord(c) ^ ord(cle[i % len(cle)])
        resultat += format(xor_val, '02x')
    return resultat


def xor_dechiffrer(texte_hex, cle):
    """
    Déchiffre un texte hexadécimal avec XOR
    """
    resultat = ""
    for i in range(0, len(texte_hex), 2):
        byte_val = int(texte_hex[i:i+2], 16)
        resultat += chr(byte_val ^ ord(cle[(i // 2) % len(cle)]))
    return resultat


if __name__ == "__main__":
    print("=== Chiffrement XOR ===\n")

    message = input("Entrez le message à chiffrer: ")

    # Chiffrement
    message_chiffre = xor_chiffrer(message, CLE)
    print(f"\nMessage chiffré: {message_chiffre}")

    # Déchiffrement
    message_dechiffre = xor_dechiffrer(message_chiffre, CLE)
    print(f"Message déchiffré: {message_dechiffre}")
