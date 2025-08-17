import random
from cryptanalysis.searcher import CharacteristicSearcher

"""

Dieses Programm beinhaltet die Klasse FrameworkProvider, welche die nötigen 
Informationen und Ressourcen für die spätere Kryptoanalyse bereitstellt. 

"""


class FrameworkProvider:
    """
    Diese Klasse bietet Hilfsfunktionen für die Kryptanalyse des SPN.
    Es können somit die relevanten Schlüsselbits (Teilschlüssel) bestimmt
    werden, geeignete Charakteristiken (linear oder differentiell) erstellt
    werden, sodass alle Schlüsselbits des letzten Rundenschlüssels abgedeckt
    sind und eine beliebige Anzahl an Textpaaren generiert werden.
    """
    def __init__(self, spn, num_rounds_char, variant = 'linear', max_active_sboxes: int = None):
        """
        Initialisiert den FrameworkProvider.

        Args:
            spn: vorgegebene SPN-Instanz
            num_rounds_char: Anzahl der Runden, für welche Charakteristiken gesucht werden sollen.
            variant: Art der Analyse; linear oder differentiell.
            max_active_sboxes: optionales Limit für aktive S-Boxen bei Charakteristik Generierung
        """
        self.spn = spn
        self.num_rounds_char = num_rounds_char
        self.variant = variant
        assert variant in ('linear', 'differential')
        self.max_active_sboxes = max_active_sboxes

    def get_target_partial_subkey(self, beta: int):
        """
        Diese Methode bestimmt die aktiven Schlüsselbits des letzten Rundenschlüssels
        basierend auf der Ausgabemaske, bzw. Ausgabedifferenz der Charakteristik.
        Dazu wird analysiert, welche S-Boxen in der letzten Runde aktiv sind.
        Falls eine S-Box aktiv ist, werden die entsprechenden Bitstellen (von
        rechts gezählt) des aktiven Eingabenibbles der S-Box in einer Menge
        gesammelt. Diese Menge der aktiven Schlüsselbits wird am Ende zurück-
        gegeben.

        Args:
            beta: Ausgabemaske/Ausgabedifferenz
        """
        affected_key_bits = set()

        for sbox_index in range(4):
            nibble_mask = (beta >> (sbox_index * 4)) & 0xF
            if nibble_mask != 0:
                for bit in range(4):
                    bit_position = sbox_index * 4 + bit
                    affected_key_bits.add(bit_position)
        return affected_key_bits

    def generate_characteristics(self):
        """
        Diese Methode sucht vier Charakteristiken mithilfe des CharacteristicSearcher,
        sodass jedes Nibble der S-Box Eingabe der letzten Runde mindestens einmal aktiv
        ist. Dadurch wird jedes Schlüsselbit des letzten Rundenschlüssels mindestens
        einmal in Betracht genommen und somit kann bei der Analyse der komplette letzte
        Rundenschlüssel ausfindig gemacht werden.

        Die Charakteristiken werden als Tripel der Form (Eingabemaske, Ausgabemaske, Bias),
        bzw. (Eingabedifferenz, Ausgabedifferenz, Wahrscheinlichkeit) in einer Liste ge-
        sammelt und zurückgegeben.
        """
        masks = []

        for i in range(4):
            searcher = CharacteristicSearcher(self.spn, self.num_rounds_char, variant=self.variant, max_active_sboxes=self.max_active_sboxes)
            searcher.add_mandatory_nibble([i])
            found = searcher.search_best_characteristic(num_solutions=1, show_results=False)

            alpha, beta, bias = found[0]
            masks.append((alpha, beta, bias))
        return masks

    def generate_samples(self, num_samples, alpha):
        """
        Diese Methode generiert die benötigten Textpaare für die
        Kryptoanalyse, indem zufällige 16-Bit-Bitstrings generiert
        werden, welche anschliessend mit dem SPN verschlüsselt
        werden.

        Die Textpaare werden in Form einer Liste zurückgegeben.

        Args:
            num_samples: Anzahl der zu generierenden Textpaare
        """
        if self.variant == 'linear':
            plaintexts = [random.randint(0, 0xFFFF) for _ in range(num_samples)]
            ciphertexts = [self.spn.encrypt(pt, self.spn.rounds) for pt in plaintexts]

            samples = list(zip(plaintexts, ciphertexts))
            return samples

        if self.variant == 'differential':
            plaintexts = [random.randint(0, 0xFFFF) for _ in range(num_samples)]
            ciphertexts = [self.spn.encrypt(pt, self.spn.rounds) for pt in plaintexts]

            plaintexts_alpha = [pt ^ alpha for pt in plaintexts]
            ciphertexts_alpha = [self.spn.encrypt(pt_alpha, self.spn.rounds) for pt_alpha in plaintexts_alpha]

            samples = list(zip(ciphertexts, ciphertexts_alpha))
            return samples