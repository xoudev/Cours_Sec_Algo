# Comprendre le Chiffrement XOR

## Qu'est-ce que XOR ?

XOR (eXclusive OR) est une opération logique binaire. Elle retourne **1** si les deux bits sont **différents**, sinon **0**.

| A | B | A XOR B |
|---|---|---------|
| 0 | 0 |    0    |
| 0 | 1 |    1    |
| 1 | 0 |    1    |
| 1 | 1 |    0    |

En Python, l'opérateur XOR est `^`.

---

## Exemple concret avec des lettres

Prenons la lettre **'H'** et la clé **'K'** :

### Étape 1 : Convertir en code ASCII
- `'H'` → `72` en décimal
- `'K'` → `75` en décimal

### Étape 2 : Convertir en binaire
- `72` → `01001000`
- `75` → `01001011`

### Étape 3 : Appliquer XOR bit à bit
```
  01001000  (H = 72)
^ 01001011  (K = 75)
----------
  00000011  (résultat = 3)
```

Le résultat est `3`, qui correspond au caractère non-imprimable `ETX` (End of Text).

---

## Pourquoi XOR est réversible ?

C'est la **magie** de XOR : appliquer deux fois la même opération redonne l'original !

```
Message XOR Clé = Chiffré
Chiffré XOR Clé = Message
```

### Preuve avec notre exemple :
```
  00000011  (chiffré = 3)
^ 01001011  (K = 75)
----------
  01001000  (H = 72) ← On retrouve H !
```

---

## Visualisation du processus complet

```
Message:  "HELLO"
Clé:      "KEY"

Étape par étape :
┌─────────┬─────┬─────────┬─────────┬──────────┐
│ Lettre  │ Clé │ ASCII M │ ASCII K │ Résultat │
├─────────┼─────┼─────────┼─────────┼──────────┤
│    H    │  K  │   72    │   75    │    3     │
│    E    │  E  │   69    │   69    │    0     │
│    L    │  Y  │   76    │   89    │   21     │
│    L    │  K  │   76    │   75    │    7     │  ← La clé recommence
│    O    │  E  │   79    │   69    │   10     │
└─────────┴─────┴─────────┴─────────┴──────────┘

La clé "KEY" se répète : K-E-Y-K-E-Y-K-E-Y...
```

---

## Code Python expliqué

```python
def xor_chiffrer(texte, cle):
    resultat = []

    for i, caractere in enumerate(texte):
        # Trouver la lettre de la clé correspondante (avec rotation)
        lettre_cle = cle[i % len(cle)]

        # XOR entre les codes ASCII
        code_chiffre = ord(caractere) ^ ord(lettre_cle)

        resultat.append(code_chiffre)

    return bytes(resultat)
```

### L'astuce `i % len(cle)` :
```
i = 0 → 0 % 3 = 0 → cle[0] = 'K'
i = 1 → 1 % 3 = 1 → cle[1] = 'E'
i = 2 → 2 % 3 = 2 → cle[2] = 'Y'
i = 3 → 3 % 3 = 0 → cle[0] = 'K'  ← Recommence !
i = 4 → 4 % 3 = 1 → cle[1] = 'E'
...
```

---

## Pourquoi encoder en Base64 ?

Le résultat du XOR peut contenir des **caractères non-imprimables** (comme le caractère `3` dans notre exemple).

Base64 convertit ces octets en caractères lisibles :
- Entrée : `[3, 0, 21, 7, 10]`
- Sortie : `AwAVBwo=`

---

## Forces et faiblesses

### ✅ Avantages
- Simple à implémenter
- Rapide
- Symétrique (même fonction pour chiffrer/déchiffrer)

### ❌ Faiblesses
- Si la clé est plus courte que le message → vulnérable à l'analyse fréquentielle
- Si on connaît une partie du message → on peut retrouver la clé
- Clé réutilisée = catastrophe sécuritaire

---

## Exercice pratique

Essayez de calculer à la main :

```
Message: "AB"
Clé: "X"

A = 65 en ASCII
B = 66 en ASCII
X = 88 en ASCII

A XOR X = ?
B XOR X = ?
```

<details>
<summary>Solution</summary>

```
65 XOR 88 = 25  (caractère EM)
66 XOR 88 = 26  (caractère SUB)
```
</details>
