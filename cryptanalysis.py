"""

Dieses Modul implementiert die lineare und differentielle Kryptanalyse für ein SPN.
Es nutzt das aus der Klasse FrameworkProvider hergestellte Framework.

"""


class Cryptanalysis:
    def __init__(self, framework):
        """
        Initialisiert die Kryptoanalyse und übernimmt das
        SPN und die gewählte Variante (linear oder differentiell)
        des Frameworks für die Analyse.
        """
        self.framework = framework
        self.spn = framework.spn
        self.variant = framework.variant

    def _partially_decrypt(self, samples, key_guess):
        """
        Diese Hilfsmethode führt eine partielle Entschlüsselung
        mit den vom FrameworkProvider hergestellten Textpaare
        der letzten Runde durch.

        Danach werden die Textpaare, bzw. Zwischentextpaare als Liste
        zurückgegeben, die zur Analyse verwendet werden.
        """
        if self.variant == 'linear':
            plaintexts = []
            partially_decrypted_ciphertexts = []

            for pt, ct in samples:
                state = ct ^ key_guess
                state = self.spn._inv_substitution(state)

                plaintexts.append(pt)
                partially_decrypted_ciphertexts.append(state)
            return plaintexts, partially_decrypted_ciphertexts

        if self.variant == 'differential':
            partially_decrypted_ciphertexts = []
            partially_decrypted_ciphertexts_alpha = []

            for sample in samples:
                (ct, ct_alpha) = sample
                state = ct ^ key_guess
                state_alpha = ct_alpha ^ key_guess

                state = self.spn._inv_substitution(state)
                state_alpha = self.spn._inv_substitution(state_alpha)

                partially_decrypted_ciphertexts.append(state)
                partially_decrypted_ciphertexts_alpha.append(state_alpha)
                
            return partially_decrypted_ciphertexts, partially_decrypted_ciphertexts_alpha

    def _find_key_bits(self, alpha, beta, attack_samples, show_results=False):
        """
        Diese Methode ist der Kern der Analyse. Sie führt die lineare oder differentielle
        Analyse mit einer gegebenen Charakteristik (alpha, beta) durch. Dazu werden die
        aktiven Key-Bits ermittelt und anschliessend werden alle möglichen Kombinationen
        dieser Key-Bits mit den partiell entschlüsselten Textpaaren getestet. Jeder
        Schlüsselvermutung (key_guess) wird ein Bias, bzw. eine Wahrscheinlichkeit
        zugeordnet, sodass anschliessend der Schlüsselkandidat mit höchstem Wert aus-
        gewählt werden kann.

        Zurückgegeben werden die ausfindig gemachten Schlüsselbits (recovered_bits)
        und das Mass deren Qualität (bias_max, bzw. prob_max).

        Args:
            alpha: Eingabemaske, bzw. Eingabedifferenz
            beta: Ausgabemaske, bzw. Ausgabedifferenz
            attack_samples: Die zu testenden Textpaare
            show_results: optionale Ausgabe der Zwischenresultate
        """
        active_bits = list(self.framework.get_target_partial_subkey(beta))

        best_key_guess = 0
        bias_max = 0
        prob_max = 0

        for guess in range(1 << len(active_bits)):
            key_guess = 0
            for i, bit_pos in enumerate(active_bits):
                if (guess >> i) & 1:
                    key_guess |= (1 << bit_pos)

            count = 0

            if self.variant == 'linear':
                for pt, partial_ct in zip(*self._partially_decrypt(attack_samples, key_guess)):
                    in_parity = bin(alpha & pt).count("1") % 2
                    out_parity = bin(beta & partial_ct).count("1") % 2
                    if in_parity == out_parity:
                        count += 1

                N = len(attack_samples)
                bias_key = (count / N) - 0.5

                if bias_key > bias_max:
                    bias_max = bias_key
                    best_key_guess = key_guess

            if self.variant == 'differential':
                for partial_ct, partial_ct_alpha in zip(*self._partially_decrypt(attack_samples, key_guess)):
                    dy = partial_ct ^ partial_ct_alpha
                    if dy == beta:
                        count += 1

                N = len(attack_samples)
                prob_key = count / N

                if prob_key > prob_max:
                    prob_max = prob_key
                    best_key_guess = key_guess

        recovered_bits = {}

        for i, bit_pos in enumerate(active_bits):
            recovered_bits[bit_pos] = (best_key_guess >> bit_pos) & 1

        if show_results:
            if self.variant == 'linear':
                print(f"target partial subkey: {active_bits}, best guess: {best_key_guess:04x} with bias: {bias_max:.10f}")
            if self.variant == 'differential':
                print(f"target partial subkey: {active_bits}, best guess: {best_key_guess:04x} with prob: {prob_max:.10f}")

        if self.variant == 'linear':
            return recovered_bits, bias_max
        if self.variant == 'differential':
            return recovered_bits, prob_max

    def find_last_round_key(self, num_attack_samples):
        """
        Diese Methode führt die lineare, bzw. differentielle Analyse für mehrere Charakteristiken
        durch und rekonstruiert den gesamten letzten Rundenschlüssel unter Kombination der
        Ergebnisse. Vorerst werden die Charakteristiken mithilfe des FrameworkProviders erstellt,
        wobei danach für jede Charakteristik Textpaare zur Analyse und die aktiven Schlüsselbits
        bestimmt werden. Danach wird mit der Hilfsmethode _find_key_bits die Analyse mit jeder
        Charakteristik durchgeführt und die gefundenen Schlüsselbits werden in einem Set gespeichert.

        Danach wird der Schlüssel rekonstruiert, indem die gefundenen Schlüsselbits zusammengesetzt
        werden. Falls mehrere Resultate für eine Schlüssel-Bitposition vorbestehen, wird das Resultat
        mit höherer Qualität (Bias, bzw. Wahrscheinlichkeit) übernommen.

        Der finale rekonstruierte Rundenschlüssel wird anschliessend zurückgegeben

        Args:
            num_attack_samples: Anzahl zu testender Textpaare
        """
        characteristics = self.framework.generate_characteristics()
        recovered_key_bits = {}  #bit_pos: (bit_value, bias_key)

        for alpha, beta, _ in characteristics:
            attack_samples = self.framework.generate_samples(num_attack_samples, alpha)
            key_bit_guesses, bias_key = self._find_key_bits(alpha, beta, attack_samples)

            for bit_pos, bit_value in key_bit_guesses.items():
                # Wenn Bitstelle noch nicht vorhanden, dann hinzufügen
                if bit_pos not in recovered_key_bits:
                    recovered_key_bits[bit_pos] = (bit_value, bias_key)
                else:
                    # Wenn neuer Bias höher, dann ersetzen
                    _, existing_bias = recovered_key_bits[bit_pos]
                    if bias_key > existing_bias:
                        recovered_key_bits[bit_pos] = (bit_value, bias_key)

        final_key = 0
        for bit_pos, (bit_val, _) in recovered_key_bits.items():
            if bit_val:
                final_key |= (1 << bit_pos)
        return final_key