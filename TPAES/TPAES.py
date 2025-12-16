"""
Programme de chiffrement AES en mode ECB et CBC pour images
Utilise une génération sécurisée de clé et IV
"""

import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PIL import Image
import argparse


def generate_key(key_size: int = 256) -> bytes:
    """Génère une clé AES sécurisée."""
    if key_size not in [128, 192, 256]:
        raise ValueError("La taille de clé doit être 128, 192 ou 256 bits")
    return os.urandom(key_size // 8)


def generate_iv() -> bytes:
    """Génère un IV sécurisé de 16 bytes."""
    return os.urandom(16)


def pad_data(data: bytes, block_size: int = 16) -> bytes:
    """Applique le padding PKCS7."""
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length] * padding_length)


def unpad_data(data: bytes) -> bytes:
    """Retire le padding PKCS7."""
    padding_length = data[-1]
    return data[:-padding_length]


def encrypt_ecb(data: bytes, key: bytes) -> bytes:
    """Chiffre en mode ECB."""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad_data(data)
    return encryptor.update(padded_data) + encryptor.finalize()


def decrypt_ecb(data: bytes, key: bytes) -> bytes:
    """Déchiffre en mode ECB."""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()
    return unpad_data(decrypted)


def encrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Chiffre en mode CBC."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad_data(data)
    return encryptor.update(padded_data) + encryptor.finalize()


def decrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Déchiffre en mode CBC."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()
    return unpad_data(decrypted)


def encrypt_image(input_path: str, output_path: str, key: bytes, mode: str, iv: bytes = None):
    """
    Chiffre une image.
    Sauvegarde:
    - Une image PNG pour visualiser le chiffrement
    - Un fichier .enc avec les données chiffrées brutes pour le déchiffrement
    """
    img = Image.open(input_path)
    img = img.convert('RGB')

    width, height = img.size
    pixels = img.tobytes()

    # Chiffrer les données
    if mode.lower() == 'ecb':
        encrypted_pixels = encrypt_ecb(pixels, key)
    elif mode.lower() == 'cbc':
        if iv is None:
            raise ValueError("IV requis pour le mode CBC")
        encrypted_pixels = encrypt_cbc(pixels, key, iv)
    else:
        raise ValueError("Mode doit être 'ecb' ou 'cbc'")

    # Sauvegarder les données chiffrées brutes (pour déchiffrement)
    enc_path = output_path.rsplit('.', 1)[0] + '.enc'
    metadata = {
        'width': width,
        'height': height,
        'mode': mode,
        'original_size': len(pixels)
    }
    with open(enc_path, 'wb') as f:
        # Écrire les métadonnées en JSON puis les données chiffrées
        meta_json = json.dumps(metadata).encode()
        f.write(len(meta_json).to_bytes(4, 'big'))
        f.write(meta_json)
        f.write(encrypted_pixels)

    # Créer l'image visuelle (tronquée pour l'affichage)
    visual_pixels = encrypted_pixels[:len(pixels)]
    encrypted_img = Image.frombytes('RGB', (width, height), visual_pixels)
    encrypted_img.save(output_path)

    print(f"Image chiffrée (visuel): {output_path}")
    print(f"Données chiffrées: {enc_path}")


def decrypt_image(input_path: str, output_path: str, key: bytes, mode: str, iv: bytes = None):
    """
    Déchiffre une image depuis le fichier .enc
    """
    # Chercher le fichier .enc correspondant
    if input_path.endswith('.enc'):
        enc_path = input_path
    else:
        enc_path = input_path.rsplit('.', 1)[0] + '.enc'

    if not os.path.exists(enc_path):
        raise FileNotFoundError(f"Fichier chiffré non trouvé: {enc_path}")

    # Lire les données chiffrées
    with open(enc_path, 'rb') as f:
        meta_len = int.from_bytes(f.read(4), 'big')
        meta_json = f.read(meta_len)
        metadata = json.loads(meta_json.decode())
        encrypted_pixels = f.read()

    width = metadata['width']
    height = metadata['height']
    original_size = metadata['original_size']

    # Déchiffrer
    if mode.lower() == 'ecb':
        decrypted_pixels = decrypt_ecb(encrypted_pixels, key)
    elif mode.lower() == 'cbc':
        if iv is None:
            raise ValueError("IV requis pour le mode CBC")
        decrypted_pixels = decrypt_cbc(encrypted_pixels, key, iv)
    else:
        raise ValueError("Mode doit être 'ecb' ou 'cbc'")

    # Tronquer à la taille originale
    decrypted_pixels = decrypted_pixels[:original_size]

    # Recréer l'image
    decrypted_img = Image.frombytes('RGB', (width, height), decrypted_pixels)
    decrypted_img.save(output_path)

    print(f"Image déchiffrée: {output_path}")


def save_key_iv(key: bytes, iv: bytes, filepath: str):
    """Sauvegarde la clé et l'IV."""
    with open(filepath, 'wb') as f:
        f.write(key)
        if iv:
            f.write(iv)
    print(f"Clé et IV sauvegardés: {filepath}")


def load_key_iv(filepath: str, key_size: int = 256) -> tuple:
    """Charge la clé et l'IV."""
    key_bytes = key_size // 8
    with open(filepath, 'rb') as f:
        data = f.read()
    key = data[:key_bytes]
    iv = data[key_bytes:key_bytes + 16] if len(data) > key_bytes else None
    return key, iv


def demo():
    """Démonstration ECB vs CBC."""
    print("=" * 60)
    print("Démonstration AES ECB vs CBC sur image")
    print("=" * 60)

    key = generate_key(256)
    iv = generate_iv()

    print(f"\nClé (hex): {key.hex()}")
    print(f"IV (hex): {iv.hex()}")

    save_key_iv(key, iv, "key_iv.bin")

    test_image = "test_image.png"
    if not os.path.exists(test_image):
        print(f"\nCréation image de test: {test_image}")
        img = Image.new('RGB', (256, 256))
        pixels = img.load()
        for x in range(256):
            for y in range(256):
                if (x // 32 + y // 32) % 2 == 0:
                    pixels[x, y] = (255, 0, 0)
                else:
                    pixels[x, y] = (0, 0, 255)
        img.save(test_image)

    print("\n--- Chiffrement ECB ---")
    encrypt_image(test_image, "encrypted_ecb.png", key, "ecb")

    print("\n--- Chiffrement CBC ---")
    encrypt_image(test_image, "encrypted_cbc.png", key, "cbc", iv)

    print("\n--- Déchiffrement ECB ---")
    decrypt_image("encrypted_ecb.png", "decrypted_ecb.png", key, "ecb")

    print("\n--- Déchiffrement CBC ---")
    decrypt_image("encrypted_cbc.png", "decrypted_cbc.png", key, "cbc", iv)

    print("\n" + "=" * 60)
    print("ECB: Les motifs répétitifs sont visibles (vulnérable)")
    print("CBC: Bruit aléatoire (sécurisé)")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Chiffrement AES (ECB/CBC) pour images")
    subparsers = parser.add_subparsers(dest='command', help='Commandes')

    # encrypt
    enc = subparsers.add_parser('encrypt', help='Chiffrer une image')
    enc.add_argument('input', help='Image source')
    enc.add_argument('output', help='Image de sortie')
    enc.add_argument('--mode', choices=['ecb', 'cbc'], default='cbc')
    enc.add_argument('--key-file', help='Fichier clé (génère si absent)')
    enc.add_argument('--key-size', type=int, default=256, choices=[128, 192, 256])

    # decrypt
    dec = subparsers.add_parser('decrypt', help='Déchiffrer une image')
    dec.add_argument('input', help='Image/fichier chiffré (.enc)')
    dec.add_argument('output', help='Image de sortie')
    dec.add_argument('--mode', choices=['ecb', 'cbc'], default='cbc')
    dec.add_argument('--key-file', required=True, help='Fichier clé')
    dec.add_argument('--key-size', type=int, default=256, choices=[128, 192, 256])

    # demo
    subparsers.add_parser('demo', help='Démonstration ECB vs CBC')

    # genkey
    gen = subparsers.add_parser('genkey', help='Générer une clé')
    gen.add_argument('output', help='Fichier de sortie')
    gen.add_argument('--key-size', type=int, default=256, choices=[128, 192, 256])

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
