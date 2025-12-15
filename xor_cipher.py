"""
Algorithme de chiffrement XOR
Simple et symétrique : même fonction pour chiffrer et déchiffrer
"""

import base64


def xor_chiffrer(texte, cle):
    """
    Chiffre un texte avec XOR et retourne le résultat en base64

    Args:
        texte: Le message à chiffrer
        cle: La clé de chiffrement

    Returns:
        Le texte chiffré encodé en base64
    """
    resultat = bytes([ord(c) ^ ord(cle[i % len(cle)]) for i, c in enumerate(texte)])
    return base64.b64encode(resultat).decode()


def xor_dechiffrer(texte_b64, cle):
    """
    Déchiffre un texte encodé en base64 avec XOR

    Args:
        texte_b64: Le message chiffré en base64
        cle: La clé de déchiffrement

    Returns:
        Le texte déchiffré
    """
    data = base64.b64decode(texte_b64)
    return ''.join(chr(b ^ ord(cle[i % len(cle)])) for i, b in enumerate(data))


if __name__ == "__main__":
    # Démonstration
    print("=== Chiffrement XOR ===\n")

    message = input("Entrez le message à chiffrer: ")
    cle = input("Entrez la clé: ")

    # Chiffrement
    message_chiffre = xor_chiffrer(message, cle)
    print(f"\nMessage chiffré (base64): {message_chiffre}")

    # Déchiffrement
    message_dechiffre = xor_dechiffrer(message_chiffre, cle)
    print(f"Message déchiffré: {message_dechiffre}")
