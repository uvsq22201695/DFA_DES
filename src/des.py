from bitstring import BitArray
from src.tables import PC1, PC2, SHIFT_VALUES, IP_TABLE, IP_INV_TABLE, EXPANSION_E, PERMUTATION_P
from src.utils import permute, get_sbox_output

class DES:
    """Implémentation de l'algorithme cryptographique DES"""

    def __init__(self, key: BitArray):
        """Initialise l'instance et calcule les 16 sous-clés."""
        self.subkeys = self._generate_subkeys(key)

    def _left_shift(self, bits: BitArray, n: int) -> BitArray:
        """Applique une rotation circulaire gauche de n bits."""
        return bits[n:] + bits[:n]

    def _generate_subkeys(self, key: BitArray) -> list[BitArray]:
        """Génère les 16 sous-clés de 48 bits."""
        permuted_key = permute(key, PC1)
        C, D = permuted_key[:28], permuted_key[28:]

        subkeys = []
        for shift in SHIFT_VALUES:
            C = self._left_shift(C, shift)
            D = self._left_shift(D, shift)
            subkeys.append(permute(C + D, PC2))

        return subkeys

    def _feistel_function(self, R: BitArray, K: BitArray) -> BitArray:
        """Fonction de Feistel f(R, K)."""
        expanded_R = permute(R, EXPANSION_E)
        
        # XOR 
        xored = expanded_R ^ K

        s_output = BitArray()
        for i in range(8):
            chunk_val = xored[i*6 : (i+1)*6].uint
            val = get_sbox_output(i, chunk_val)
            s_output.append(BitArray(uint=val, length=4))

        return permute(s_output, PERMUTATION_P)

    def encrypt(self, plaintext: BitArray) -> BitArray:
        """Algorithme de chiffrement d'un bloc de 64 bits."""
        permuted = permute(plaintext, IP_TABLE)
        L, R = permuted[:32], permuted[32:]

        for i in range(16):
            prev_R = R
            f_res = self._feistel_function(R, self.subkeys[i])
            R = L ^ f_res
            L = prev_R

        combined = R + L
        return permute(combined, IP_INV_TABLE)

    def decrypt(self, ciphertext: BitArray) -> BitArray:
        """Algorithme de déchiffrement d'un bloc de 64 bits."""
        permuted = permute(ciphertext, IP_TABLE)
        L, R = permuted[:32], permuted[32:]

        for i in range(15, -1, -1):
            current_R = R
            f_res = self._feistel_function(R, self.subkeys[i])
            R = L ^ f_res
            L = current_R

        combined = R + L
        return permute(combined, IP_INV_TABLE)