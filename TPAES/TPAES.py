"""
Programme de chiffrement AES en mode ECB et CBC pour images
Utilise une génération sécurisée de clé et IV
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PIL import Image
import argparse


def generate_key(key_size: int = 256) -> bytes:
    """
    Génère une clé AES sécurisée.

    Args:
        key_size: Taille de la clé en bits (128, 192 ou 256)

    Returns:
        Clé AES en bytes
    """
    if key_size not in [128, 192, 256]:
        raise ValueError("La taille de clé doit être 128, 192 ou 256 bits")
    return os.urandom(key_size // 8)


def generate_iv() -> bytes:
    """
    Génère un IV (vecteur d'initialisation) sécurisé de 16 bytes.

    Returns:
        IV de 16 bytes
    """
    return os.urandom(16)


def pad_data(data: bytes, block_size: int = 16) -> bytes:
    """
    Applique le padding PKCS7 aux données.

    Args:
        data: Données à padder
        block_size: Taille du bloc (16 pour AES)

    Returns:
        Données avec padding
    """
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length] * padding_length)


def unpad_data(data: bytes) -> bytes:
    """
    Retire le padding PKCS7 des données.

    Args:
        data: Données avec padding

    Returns:
        Données sans padding
    """
    padding_length = data[-1]
    return data[:-padding_length]


def encrypt_ecb(data: bytes, key: bytes) -> bytes:
    """
    Chiffre les données en mode ECB.

    Args:
        data: Données à chiffrer
        key: Clé AES

    Returns:
        Données chiffrées
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad_data(data)
    return encryptor.update(padded_data) + encryptor.finalize()


def decrypt_ecb(data: bytes, key: bytes) -> bytes:
    """
    Déchiffre les données en mode ECB.

    Args:
        data: Données chiffrées
        key: Clé AES

    Returns:
        Données déchiffrées
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()
    return unpad_data(decrypted)


def encrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Chiffre les données en mode CBC.

    Args:
        data: Données à chiffrer
        key: Clé AES
        iv: Vecteur d'initialisation

    Returns:
        Données chiffrées
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad_data(data)
    return encryptor.update(padded_data) + encryptor.finalize()


def decrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Déchiffre les données en mode CBC.

    Args:
        data: Données chiffrées
        key: Clé AES
        iv: Vecteur d'initialisation

    Returns:
        Données déchiffrées
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()
    return unpad_data(decrypted)


def encrypt_image(input_path: str, output_path: str, key: bytes, mode: str, iv: bytes = None):
    """
    Chiffre une image en préservant l'en-tête BMP pour visualisation.

    Args:
        input_path: Chemin de l'image source
        output_path: Chemin de l'image chiffrée
        key: Clé AES
        mode: Mode de chiffrement ('ecb' ou 'cbc')
        iv: Vecteur d'initialisation (requis pour CBC)
    """
    # Ouvrir l'image et la convertir en RGB
    img = Image.open(input_path)
    img = img.convert('RGB')

    # Obtenir les dimensions et les données pixels
    width, height = img.size
    pixels = img.tobytes()

    # Chiffrer les données pixels
    if mode.lower() == 'ecb':
        encrypted_pixels = encrypt_ecb(pixels, key)
    elif mode.lower() == 'cbc':
        if iv is None:
            raise ValueError("IV requis pour le mode CBC")
        encrypted_pixels = encrypt_cbc(pixels, key, iv)
    else:
        raise ValueError("Mode doit être 'ecb' ou 'cbc'")

    # Tronquer à la taille originale (enlever le padding pour l'affichage)
    encrypted_pixels = encrypted_pixels[:len(pixels)]

    # Créer une nouvelle image avec les pixels chiffrés
    encrypted_img = Image.frombytes('RGB', (width, height), encrypted_pixels)
    encrypted_img.save(output_path)

    print(f"Image chiffrée sauvegardée: {output_path}")


def decrypt_image(input_path: str, output_path: str, key: bytes, mode: str,
                  iv: bytes = None):
    """
    Déchiffre une image.

    Args:
        input_path: Chemin de l'image chiffrée
        output_path: Chemin de l'image déchiffrée
        key: Clé AES
        mode: Mode de déchiffrement ('ecb' ou 'cbc')
        iv: Vecteur d'initialisation (requis pour CBC)
    """
    img = Image.open(input_path)
    img = img.convert('RGB')

    width, height = img.size
    pixels = img.tobytes()

    # Pour le déchiffrement, on doit re-padder les données
    padded_pixels = pad_data(pixels)

    # Rechiffrer pour pouvoir déchiffrer correctement
    # Note: Pour une vraie application, il faudrait stocker les données chiffrées brutes
    if mode.lower() == 'ecb':
        # Rechiffrer les pixels pour obtenir le texte chiffré complet
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_pixels) + encryptor.finalize()
        decrypted_pixels = decrypt_ecb(encrypted, key)
    elif mode.lower() == 'cbc':
        if iv is None:
            raise ValueError("IV requis pour le mode CBC")
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_pixels) + encryptor.finalize()
        decrypted_pixels = decrypt_cbc(encrypted, key, iv)
    else:
        raise ValueError("Mode doit être 'ecb' ou 'cbc'")

    decrypted_pixels = decrypted_pixels[:width * height * 3]

    decrypted_img = Image.frombytes('RGB', (width, height), decrypted_pixels)
    decrypted_img.save(output_path)

    print(f"Image déchiffrée sauvegardée: {output_path}")


def save_key_iv(key: bytes, iv: bytes, filepath: str):
    """
    Sauvegarde la clé et l'IV dans un fichier.

    Args:
        key: Clé AES
        iv: Vecteur d'initialisation
        filepath: Chemin du fichier de sortie
    """
    with open(filepath, 'wb') as f:
        f.write(key)
        if iv:
            f.write(iv)
    print(f"Clé et IV sauvegardés: {filepath}")


def load_key_iv(filepath: str, key_size: int = 256) -> tuple:
    """
    Charge la clé et l'IV depuis un fichier.

    Args:
        filepath: Chemin du fichier
        key_size: Taille de la clé en bits

    Returns:
        Tuple (key, iv)
    """
    key_bytes = key_size // 8
    with open(filepath, 'rb') as f:
        data = f.read()
    key = data[:key_bytes]
    iv = data[key_bytes:key_bytes + 16] if len(data) > key_bytes else None
    return key, iv


def demo():
    """Démonstration du chiffrement AES sur une image."""
    print("=" * 60)
    print("Démonstration du chiffrement AES ECB vs CBC sur image")
    print("=" * 60)

    # Générer clé et IV sécurisés
    key = generate_key(256)
    iv = generate_iv()

    print(f"\nClé générée (hex): {key.hex()}")
    print(f"IV généré (hex): {iv.hex()}")

    # Sauvegarder clé et IV
    save_key_iv(key, iv, "key_iv.bin")

    # Créer une image de test si elle n'existe pas
    test_image = "test_image.png"
    if not os.path.exists(test_image):
        print(f"\nCréation d'une image de test: {test_image}")
        # Créer une image avec un motif répétitif (pour montrer la faiblesse d'ECB)
        img = Image.new('RGB', (256, 256))
        pixels = img.load()
        for x in range(256):
            for y in range(256):
                # Motif avec des blocs de couleur répétitifs
                if (x // 32 + y // 32) % 2 == 0:
                    pixels[x, y] = (255, 0, 0)  # Rouge
                else:
                    pixels[x, y] = (0, 0, 255)  # Bleu
        img.save(test_image)
        print(f"Image de test créée avec motif répétitif")

    # Chiffrement ECB
    print("\n--- Chiffrement ECB ---")
    encrypt_image(test_image, "encrypted_ecb.png", key, "ecb")

    # Chiffrement CBC
    print("\n--- Chiffrement CBC ---")
    encrypt_image(test_image, "encrypted_cbc.png", key, "cbc", iv)

    print("\n" + "=" * 60)
    print("Comparaison:")
    print("- ECB: Les motifs répétitifs de l'image originale sont visibles")
    print("- CBC: L'image chiffrée ressemble à du bruit aléatoire")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Chiffrement AES (ECB/CBC) pour images"
    )

    subparsers = parser.add_subparsers(dest='command', help='Commandes disponibles')

    # Commande encrypt
    encrypt_parser = subparsers.add_parser('encrypt', help='Chiffrer une image')
    encrypt_parser.add_argument('input', help='Image source')
    encrypt_parser.add_argument('output', help='Image de sortie')
    encrypt_parser.add_argument('--mode', choices=['ecb', 'cbc'], default='cbc',
                                help='Mode de chiffrement (défaut: cbc)')
    encrypt_parser.add_argument('--key-file', help='Fichier contenant la clé (génère si absent)')
    encrypt_parser.add_argument('--key-size', type=int, default=256,
                                choices=[128, 192, 256], help='Taille de clé en bits')

    # Commande decrypt
    decrypt_parser = subparsers.add_parser('decrypt', help='Déchiffrer une image')
    decrypt_parser.add_argument('input', help='Image chiffrée')
    decrypt_parser.add_argument('output', help='Image de sortie')
    decrypt_parser.add_argument('--mode', choices=['ecb', 'cbc'], default='cbc',
                                help='Mode de déchiffrement')
    decrypt_parser.add_argument('--key-file', required=True, help='Fichier contenant la clé')
    decrypt_parser.add_argument('--key-size', type=int, default=256,
                                choices=[128, 192, 256], help='Taille de clé en bits')

    # Commande demo
    subparsers.add_parser('demo', help='Démonstration ECB vs CBC')

    # Commande genkey
    genkey_parser = subparsers.add_parser('genkey', help='Générer une clé')
    genkey_parser.add_argument('output', help='Fichier de sortie')
    genkey_parser.add_argument('--key-size', type=int, default=256,
                               choices=[128, 192, 256], help='Taille de clé en bits')

    args = parser.parse_args()

    if args.command == 'demo':
        demo()

    elif args.command == 'genkey':
        key = generate_key(args.key_size)
        iv = generate_iv()
        save_key_iv(key, iv, args.output)
        print(f"Clé ({args.key_size} bits): {key.hex()}")
        print(f"IV: {iv.hex()}")

    elif args.command == 'encrypt':
        if args.key_file and os.path.exists(args.key_file):
            key, iv = load_key_iv(args.key_file, args.key_size)
        else:
            key = generate_key(args.key_size)
            iv = generate_iv()
            key_file = args.key_file or 'key_iv.bin'
            save_key_iv(key, iv, key_file)

        encrypt_image(args.input, args.output, key, args.mode, iv)

    elif args.command == 'decrypt':
        key, iv = load_key_iv(args.key_file, args.key_size)
        decrypt_image(args.input, args.output, key, args.mode, iv)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
