# Cours_Sec_Algo

## Chiffrement de César

### Description

Le chiffrement de César est l'une des techniques de cryptographie les plus anciennes et les plus simples. Il s'agit d'un chiffrement par substitution où chaque lettre du texte clair est remplacée par une lettre située à une distance fixe dans l'alphabet.

### Principe de fonctionnement

- Chaque lettre est décalée d'un nombre fixe de positions (la **clé**)
- Par exemple, avec un décalage de 3 : A → D, B → E, C → F, etc.
- Le décalage est circulaire : X → A, Y → B, Z → C

### Utilisation

#### Fonctions disponibles

| Fonction | Description |
|----------|-------------|
| `caesar_encrypt(plaintext, shift)` | Chiffre le texte avec le décalage donné |
| `caesar_decrypt(ciphertext, shift)` | Déchiffre le texte avec le décalage donné |

#### Exemple

```python
from Ceasar_Encryption import caesar_encrypt, caesar_decrypt

# Chiffrement
texte = "Bonjour le monde!"
texte_chiffre = caesar_encrypt(texte, 3)
print(texte_chiffre)  # Erqmrxu oh prqgh!

# Déchiffrement
texte_dechiffre = caesar_decrypt(texte_chiffre, 3)
print(texte_dechiffre)  # Bonjour le monde!
```

#### Exécution directe

```bash
python Ceasar_Encryption.py
```

### Caractéristiques

- Préserve la casse (majuscules/minuscules)
- Les caractères non alphabétiques restent inchangés (espaces, ponctuation, chiffres)
- Gère le retour circulaire (Z + 1 = A)

### Sécurité

Le chiffrement de César est **très faible** du point de vue cryptographique :
- Seulement 25 clés possibles
- Vulnérable à l'analyse fréquentielle
- Facilement cassable par force brute

Il est utilisé à des fins **éducatives uniquement** et ne doit jamais être utilisé pour protéger des données sensibles.
