# Documentation Technique : Outil de Chiffrement et Signature PDF (AES + ECDSA)

## 1. Introduction
Ce projet a pour objectif de sécuriser des documents PDF en garantissant trois propriétés fondamentales de la sécurité informatique :
1.  **Confidentialité** : Le contenu du document est illisible pour les personnes non autorisées (via chiffrement AES).
2.  **Intégrité** : Le document n'a pas été modifié durant le transfert (via hachage SHA-256).
3.  **Authenticité et Non-répudiation** : L'auteur du document est identifié et ne peut nier avoir signé le document (via signature ECDSA).

---

## 2. Concepts Théoriques Clés

Pour votre rapport et votre présentation, il est crucial de définir les algorithmes utilisés :

### A. AES (Advanced Encryption Standard) - Chiffrement Symétrique
*   **Rôle** : Chiffrer le contenu volumineux (le fichier PDF).
*   **Fonctionnement** : Utilise une **même clé** pour chiffrer et déchiffrer. C'est très rapide.
*   **Mode CBC (Cipher Block Chaining)** : Le chiffrement se fait par blocs. Chaque bloc dépend du précédent. Cela nécessite un **IV (Vecteur d'Initialisation)** aléatoire pour que deux chiffrages du même fichier donnent des résultats différents.
*   **Padding (Remplissage)** : AES fonctionne sur des blocs de 16 octets. Si le fichier ne fait pas un multiple de 16, on ajoute du "rembourrage" (padding) à la fin.

### B. SHA-256 (Secure Hash Algorithm) - Hachage
*   **Rôle** : Créer une "empreinte digitale" unique du fichier chiffré.
*   **Fonctionnement** : Transforme n'importe quelle quantité de données en une chaîne fixe de 256 bits.
*   **Propriété** : Si on change un seul bit du fichier, le hash change complètement. C'est ce qui garantit l'intégrité.

### C. ECDSA (Elliptic Curve Digital Signature Algorithm) - Signature Asymétrique
*   **Rôle** : Signer le hash du fichier.
*   **Fonctionnement** : Repose sur une paire de clés :
    *   **Clé Privée** : Gardée secrète par l'utilisateur, elle sert à **signer**.
    *   **Clé Publique** : Partagée avec tout le monde, elle sert à **vérifier** la signature.
*   **Avantage** : ECDSA offre une sécurité équivalente à RSA mais avec des clés beaucoup plus petites (plus rapide et efficace).

---

## 3. Architecture et Flux de Données

Voici comment les données circulent dans l'application :

### Phase 1 : Chiffrement et Signature (Émetteur)
1.  **Lecture** du fichier PDF original (Clair).
2.  **Génération** d'une clé AES aléatoire (32 octets) et d'un IV (16 octets).
3.  **Chiffrement AES** : `PDF + Clé AES + IV` -> `Données Chiffrées`.
4.  **Hachage** : `SHA-256(IV + Données Chiffrées)` -> `Hash`.
5.  **Signature** : `Hash + Clé Privée ECDSA` -> `Signature`.
6.  **Sortie** : Fichier `.enc` (Contenu chiffré), Fichier `.sig` (Signature), Fichier `.aeskey` (Clé AES).

### Phase 2 : Vérification et Déchiffrement (Récepteur)
1.  **Lecture** du fichier chiffré (`.enc`) et de la signature (`.sig`).
2.  **Calcul du Hash** : Le récepteur recalcule le SHA-256 du fichier chiffré reçu.
3.  **Vérification ECDSA** : `Signature + Hash Calculé + Clé Publique` -> **Valide ou Invalide**.
    *   *Si Invalide* : Le fichier a été altéré ou la signature est fausse. Arrêt.
    *   *Si Valide* : On procède au déchiffrement.
4.  **Déchiffrement AES** : `Données Chiffrées + Clé AES` -> `PDF Original`.

---

## 4. Explication du Code (Points Techniques)

### Bibliothèques utilisées
*   `tkinter` : Pour l'interface graphique (GUI).
*   `ecdsa` : Pour la gestion des courbes elliptiques (NIST256p).
*   `Crypto.Cipher.AES` & `Crypto.Util.Padding` : Bibliothèque `pycryptodome` pour le chiffrement standardisé.

### Fonctions Principales

#### `generate_keys(self)`
Génère la paire de clés sur la courbe NIST256p.
```python
self.private_key = SigningKey.generate(curve=NIST256p)
self.public_key = self.private_key.verifying_key
```

#### `encrypt_and_sign(self)`
C'est le cœur du système. Notez l'importance de l'ordre des opérations :
1.  On chiffre d'abord (`cipher.encrypt`).
2.  On signe le résultat chiffré (Encrypt-then-Sign est une bonne pratique de sécurité).
```python
# Chiffrement
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

# Signature du hash
file_hash = hashlib.sha256(encrypted_content).digest()
signature = self.private_key.sign(file_hash)
```

#### `verify_and_decrypt(self)`
L'étape critique est la vérification **avant** le déchiffrement. On ne déchiffre pas si la signature est mauvaise.
```python
if self.public_key.verify(signature, file_hash):
    # Alors on déchiffre...
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
```

---

## 5. Guide d'Utilisation (Scénario de Démo)

Pour votre présentation, suivez ce scénario :

1.  **Lancement** : Ouvrez l'application.
2.  **Génération** : Cliquez sur "Générer une paire de clés". Montrez les fichiers `private.pem` et `public.pem` créés.
3.  **Chiffrement** :
    *   Sélectionnez un PDF.
    *   Montrez que le PDF est illisible (ouvrez le `.enc` avec un éditeur de texte pour montrer le "charabia").
4.  **Vérification** :
    *   Chargez la clé publique.
    *   Sélectionnez le fichier `.enc`.
    *   Montrez le message "Signature VALIDE" et l'ouverture du fichier déchiffré.
5.  **Test d'erreur (Optionnel mais impressionnant)** :
    *   Modifiez manuellement un octet dans le fichier `.enc` avec un éditeur hexadécimal.
    *   Tentez de vérifier/déchiffrer.
    *   L'application affichera "Signature INVALIDE", prouvant que l'intégrité est protégée.

---

## 6. Limites et Améliorations Possibles

Pour conclure un rapport académique, il faut être critique :

1.  **Gestion de la clé AES** : Actuellement, la clé AES est sauvegardée dans un fichier `.aeskey` à côté du document.
    *   *Amélioration* : Dans un système réel, cette clé AES devrait être elle-même chiffrée avec la clé publique du destinataire (Chiffrement Hybride).
2.  **Distribution des clés** : Comment s'assurer que la clé publique appartient bien à la bonne personne ?
    *   *Amélioration* : Utilisation de certificats numériques (PKI).

---
*Ce document a été généré pour servir de base à votre rapport de projet.*
