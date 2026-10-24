import unittest
from bitstring import BitArray
from src.des import DES

class TestDES(unittest.TestCase):
    def setUp(self):
        """Initialisation des variables et des instances DES."""
        
        # 1. Vecteurs de test standards
        self.std_key = BitArray(hex="0123456789ABCDEF")
        self.std_plain = BitArray(hex="4E6F772069732074")
        self.std_cipher = BitArray(hex="3FA40E8A984D4815")
        self.std_des = DES(self.std_key)

        # 2. Vecteurs spécifiques au projet
        self.proj_key = BitArray(hex="6E387CDFB057AB3B")
        self.proj_plain = BitArray(hex="FD1C382A5DC81C73")
        self.proj_cipher = BitArray(hex="1A6FCE10242797D6")
        self.proj_des = DES(self.proj_key)

    def test_standard_encryption(self):
        result = self.std_des.encrypt(self.std_plain)
        self.assertEqual(result.hex.upper(), self.std_cipher.hex.upper())

    def test_standard_decryption(self):
        result = self.std_des.decrypt(self.std_cipher)
        self.assertEqual(result.hex.upper(), self.std_plain.hex.upper())

    def test_project_encryption(self):
        result = self.proj_des.encrypt(self.proj_plain)
        self.assertEqual(result.hex.upper(), self.proj_cipher.hex.upper())

    def test_project_decryption(self):
        result = self.proj_des.decrypt(self.proj_cipher)
        self.assertEqual(result.hex.upper(), self.proj_plain.hex.upper())

if __name__ == "__main__":
    unittest.main()
    