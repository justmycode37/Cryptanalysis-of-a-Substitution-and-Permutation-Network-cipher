"""

Dieses Programm beinhaltet das grundlegende SPN, welches mit jeglicher Substitution und Permutation beliebig mit n-Runden
benutzt werden kann. Die Klasse SPN beinhaltet alle nötigen Inhalte zur Verschlüsselung
(encrypt) und Entschlüsselung (decrypt) eines beliebigen 16-Bit Eingabetextes.

Zu beachten ist, dass die letzte Runde jeweils keine Permutation beinhaltet, da diese keine weitere Sicherheit
mit sich bringt. Anstelle der Permutation in letzter Runde wird abermals ein Key Mixing durchgeführt.

"""


class SPN:
    def __init__(self, sbox, pbox, round_keys, rounds):
        """
        Initialisiert das SPN, wobei die inverse S-Box und
        P-Box für die Entschlüsselung erstellt werden.
        """
        self.sbox = sbox
        self.inv_sbox = [0] * 16
        for i, val in enumerate(sbox):
            self.inv_sbox[val] = i

        self.pbox = pbox
        self.inv_pbox = [0] * 16
        for i, val in enumerate(pbox):
            self.inv_pbox[val] = i

        self.rounds = rounds
        self.round_keys = round_keys

    def _substitution(self, state):
        """
        Führt Substitutionsvorgang durch, wobei jedes
        Nibble (4-Bit-Block) gemäss der S-Box Tabelle ersetzt wird.
        """
        output = 0
        for i in range(4):
            nibble = (state >> (i * 4)) & 0xF
            output |= self.sbox[nibble] << (i * 4)
        return output

    def _inv_substitution(self, state):
        """
        Führt den inversen Substitutionsvorgang durch, wobei jedes
        Nibble gemäss der inversen S-Box Tabelle ersetzt wird.
        """
        output = 0
        for i in range(4):
            nibble = (state >> (i * 4)) & 0xF
            output |= self.inv_sbox[nibble] << (i * 4)
        return output

    def _permutation(self, state):
        """
        Führt Permutationsvorgang durch, wobei jedes
        Bit gemäss der P-Box Tabelle vertauscht wird.
        """
        permuted = 0
        for i in range(16):
            bit = (state >> i) & 1
            permuted |= bit << self.pbox[i]
        return permuted

    def _inv_permutation(self, state):
        """
        Führt inversen Permutationsvorgang durch, wobei jedes
        Bit gemäss der inversen P-Box Tabelle vertauscht wird.
        """
        permuted = 0
        for i in range(16):
            bit = (state >> i) & 1
            permuted |= bit << self.inv_pbox[i]
        return permuted

    def encrypt(self, plaintext, num_rounds):
        """
        Verschlüsselt einen beliebigen Klartext (16-Bit), indem
        für num_rounds Runden jeweils ein Key Mixing, Substitutionsvorgang
        und Permutationsvorgang durchgeführt wird, ausser in der letzten
        Runde, bei welcher keine Permutation, jedoch anstelle dieser ein
        Key Mixing durchgeführt wird. Danach wird der Geheimtext ausgegeben.
        """
        state = plaintext
        for i in range(1, num_rounds + 1):
            state ^= self.round_keys[i - 1]
            state = self._substitution(state)
            if i != num_rounds:
                state = self._permutation(state)
        state ^= self.round_keys[num_rounds]
        return state

    def decrypt(self, ciphertext, num_rounds):
        """
        Entschlüsselt einen beliebigen Geheimtext (16-Bit), indem
        die Schritte des Verschlüsselungsvorgangs rückgängig gemacht
        werden. Verwendet inverse Substitution und Permutation und
        gibt den ursprünglichen Klartext zurück.
        """
        state = ciphertext ^ self.round_keys[num_rounds]
        for i in reversed(range(1, num_rounds + 1)):
            if i != num_rounds:
                state = self._permutation(state)
            state = self._inv_substitution(state)
            state ^= self.round_keys[i - 1]
        return state