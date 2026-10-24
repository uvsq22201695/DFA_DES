# DES Fault Attack

Implémentation d'une attaque différentielle par fautes (DFA) sur l'algorithme DES.

## Installation

1. Le projet a été développé et testé avec Python 3.14.5.
2. Installez les dépendances :
    ```Bash
    pip install -r requirements.txt
    ```

## Utilisation

Le script ``src/attack.py`` extrait la clé complète à partir d'un échantillon de chiffrés fautés :

```Bash
python -m src.attack
```

## Structure

* ``src/``: Code source de l'algorithme DES, des tables et de l'attaque.
* ``tests/``: Tests unitaires pour valider l'implémentation.
* ``requirements.txt``: Liste des dépendances nécessaires.
* ``README.md``: Documentation du projet.
