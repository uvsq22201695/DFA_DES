from bitstring import BitArray
from src.tables import EXPANSION_E, PC1, PC2, PERMUTATION_P_INV
from src.utils import extract_L16_R16, get_sbox_output, permute
from src.des import DES

def run_attack():
    chiffre_juste_hex = "1A6FCE10242797D6" 
    clair_attendu_hex = "FD1C382A5DC81C73"
    
    chiffres_faux_hex = [
        "5A6FD6102C3397D7", "0E6B8F802407D7C6", "187AC615642397C2", "5AEFDE09643393D6",
        "166F8A113433B7D6", "0A7D8F002426D7F6", "5B6FDA116C3795D7", "1E6FCF002407D7F6",
        "1B7FCC54362697D6", "4E6FDE30206F9797", "8A6FCD40252697D6", "1B0FCE56202696D6",
        "587ADE1424279FC2", "5AEFCE002467929F", "1B7BCE14362717C6", "5A6FCE10242F969E",
        "1A6A4E00A42793D6", "5A6FDA19743197D6", "7A6F4E1025679296", "1A63CE812437D7C6",
        "8B6FCB00252795D6", "1B4FCA11702396D4", "1E6A8E10A527B3D6", "1A2FCE11742197D4",
        "1E6FAF10042797D6", "1B2ACE5624A697D2", "126FEA1130338796", "0E7DCE3020269796",
        "7A6BCE1024671686", "1A72CE5524369746", "5E6F9F1000278ED6", "1A7ECE5424A69742"
    ]

    # Extraction des données du 15ème tour
    L16_juste, R16_juste = extract_L16_R16(chiffre_juste_hex)
    E_R15 = permute(L16_juste, EXPANSION_E)

    k16_candidates = [set(range(2**6)) for _ in range(8)]

    for chiffre_faux in chiffres_faux_hex:
        L16_faux, R16_faux = extract_L16_R16(chiffre_faux)
        
        diff_R16 = R16_juste ^ R16_faux
        diff_sbox_out = permute(diff_R16, PERMUTATION_P_INV)
        E_R15_faux = permute(L16_faux, EXPANSION_E)

        for i in range(8):
            in_j_val = E_R15[i*6 : (i+1)*6].uint
            in_f_val = E_R15_faux[i*6 : (i+1)*6].uint
            diff_out_val = diff_sbox_out[i*4 : (i+1)*4].uint

            if in_j_val == in_f_val:
                continue
                
            valid_k = set()
            for k in k16_candidates[i]:
                out_j = get_sbox_output(i, in_j_val ^ k)
                out_f = get_sbox_output(i, in_f_val ^ k)
                
                if (out_j ^ out_f) == diff_out_val:
                    valid_k.add(k)
                    
            k16_candidates[i] &= valid_k

    # Assemblage de la sous-clé K16
    k16_bits = BitArray()
    for candidates in k16_candidates:
        k16_bits.append(BitArray(uint=list(candidates)[0], length=6))

    cle_formatee = " ".join([k16_bits.hex.upper()[i:i+2] for i in range(0, 16, 2)])
    print(f"Clé K16 (48 bits) : {cle_formatee}")

    # Reconstruction de la clé de 64 bits par recherche exhaustive
    indices_manquants_pc2 = [i for i in range(1, 57) if i not in PC2]
    bits_clair_attendu = BitArray(hex=clair_attendu_hex)
    bits_chiffre_juste = BitArray(hex=chiffre_juste_hex)

    for guess in range(2**8):
        bits_guess = BitArray(uint=guess, length=8)
        C0D0 = BitArray(56)
        
        for idx_k16, pos_c0d0 in enumerate(PC2):
            C0D0[pos_c0d0 - 1] = k16_bits[idx_k16]
            
        for idx_guess, pos_c0d0 in enumerate(indices_manquants_pc2):
            C0D0[pos_c0d0 - 1] = bits_guess[idx_guess]
            
        cle_64_bits = BitArray(64)
        for idx_c0d0, pos_cle in enumerate(PC1):
            cle_64_bits[pos_cle - 1] = C0D0[idx_c0d0]
            
        for octet in range(8):
            somme_bits = cle_64_bits[octet*8 : octet*8 + 7].count(1)
            cle_64_bits[octet*8 + 7] = 1 if somme_bits % 2 == 0 else 0
            
        cipher_test = DES(cle_64_bits)
        if cipher_test.decrypt(bits_chiffre_juste) == bits_clair_attendu:
            cle_formatee = " ".join([cle_64_bits.hex.upper()[i:i+2] for i in range(0, 16, 2)])
            print(f"Clé complète (64 bits) : {cle_formatee}")
            return

if __name__ == "__main__":
    run_attack()
