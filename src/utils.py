from bitstring import BitArray
from src.tables import IP_TABLE, S_BOXES

def permute(block: BitArray, table: list[int]) -> BitArray:
    """Réorganise un BitArray selon une table de permutation donnée."""
    return BitArray([block[i - 1] for i in table])

def extract_L16_R16(cipher_hex: str) -> tuple[BitArray, BitArray]:
    """Annule la permutation finale IP-1 pour extraire L16 et R16 depuis l'hexadécimal."""
    block = BitArray(hex=cipher_hex)
    reversed_block = permute(block, IP_TABLE)
    return reversed_block[32:], reversed_block[:32]

def get_sbox_output(sbox_idx: int, input_val: int) -> int:
    """Calcule la sortie de 4 bits d'une S-Box à partir d'un entier de 6 bits."""
    row = ((input_val >> 4) & 2) | (input_val & 1)
    col = (input_val >> 1) & 15
    return S_BOXES[sbox_idx][row][col]