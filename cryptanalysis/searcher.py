from z3 import *
from functools import reduce

"""

Der Zweck dieses Programmes ist das Finden optimaler linearer und differentieller 
Charakteristiken (Approximationen und Differentialcharakteristiken). Dazu wird 
der Z3 Solver von Microsoft Research verwendet, welcher das Optimierungsproblem 
löst und somit qualitativ hochwertige Charakteristiken findet. 

"""


class CharacteristicSearcher:
    """
    Diese Klasse analysiert ein SPN auf seine Schwachstellen, um daraus qualitativ
    hochwertige lineare und differentielle Charakteristiken für einen potenziellen
    Angriff zu finden.

    Sie ist modular aufgebaut, sodass Approximationen, sowohl als auch Differential-
    charakteristiken mit demselben Programm eruiert werden können.

    Die Klasse erstellt ein Optimierungsmodell, welches die kryptographische Struktur
    dem SMT-Solver Z3 schildert, um Charakteristiken mit maximalem Bias (linear),
    respektive maximaler Wahrscheinlichkeit (differentiell) zu finden.
    """
    def __init__(self, spn, num_rounds: int, variant='linear', max_active_sboxes: int = None):
        """
        Initialisiert den CharacteristicSearcher.

        Args:
            spn: vorgegebene SPN-Instanz
            num_rounds: Anzahl der Runden, für welche eine Charakteristik gesucht werden soll.
            variant: Art der Analyse; linear oder differentiell.
            max_active_sboxes: optionales Limit für aktive S-Boxen.
        """
        assert variant in ('linear', 'differential')
        self.spn = spn
        self.num_rounds = num_rounds
        self.variant = variant
        self.max_active_sboxes = max_active_sboxes
        self.nibbles = 4
        self.n = 4

        self.look_up_table = self._compute_look_up_table()
        self.solver = Optimize()
        self._define_variables()
        self._add_constraints()

    def _compute_look_up_table(self):
        """
        Diese Hilfsmethode erstellt den "LAT" oder "DDT" für die
        S-Box der SPN-Instanz und speichert also für jede Eingabe-
        und Ausgabekombination bei linearer Variante den Bias und
        bei differentieller Variante die Wahrscheinlichkeit.

        Falls der Bias oder die Wahrscheinlichkeit Null ist, wird
        der Wert durch einen sehr kleinen Wert ungleich Null ersetzt,
        um ein Nullprodukt zu vermeiden, da der Z3-Solver das Produkt
        optimiert.
        """
        sbox = self.spn.sbox
        table = {}
        for alpha in range(16):
            for beta in range(16):
                count = 0
                for x in range(16):
                    if self.variant == 'linear':
                        in_parity = bin(alpha & x).count("1") % 2
                        out_parity = bin(beta & sbox[x]).count("1") % 2
                        if in_parity == out_parity:
                            count += 1
                    if self.variant == 'differential':
                        dy = sbox[x] ^ sbox[x ^ alpha]
                        if dy == beta:
                            count += 1
                prob = count / 16

                if self.variant == 'linear':
                    table[(alpha, beta)] = prob - 0.5 if prob - 0.5 != 0.0 else 0.000001
                if self.variant == 'differential':
                    table[(alpha, beta)] = prob if prob != 0 else 0.000001
        return table

    def _define_variables(self):
        """
        Definiert Z3-Variablen:
        in_masks: 16-Bit-Masken für die Eingabe jeder Runde.
        out_masks: 16-Bit-Masken für die Ausgabe jeder Runde.
        active_sboxes_per_round: Bool-Werte für aktive S-Boxen.
        """
        self.in_masks = [BitVec(f"in_{r}", 16) for r in range(self.num_rounds + 1)]
        self.out_masks = [BitVec(f"out_{r}", 16) for r in range(self.num_rounds + 1)]
        self.active_sboxes_per_round = []

    def _add_constraints(self):
        """
        Diese Methode fügt dem Optimierungsmodell Nebenbedingungen hinzu.
        Einerseits werden die Eingabe- und Ausgaberelationen der S-Box 
        festgelegt, die Permutation gefordert und die Nullmasken-Konfiguration 
        vermieden. Andererseits wird das globale Optimierungsziel festgelegt, 
        wobei optional die Anzahl aktiver S-Boxen festgelegt werden kann.
        """
        prob_terms = []
        for r in range(self.num_rounds):
            active_sboxes = []
            constraints = []

            for i in range(4):
                in_nib = Extract((i + 1) * 4 - 1, i * 4, self.in_masks[r])
                out_nib = Extract((i + 1) * 4 - 1, i * 4, self.out_masks[r])
                
                constraints.append(Implies(in_nib == 0, out_nib == 0))

                prob = Real(f"prob_r{r}_n{i}")
                val = []
                for (a, b), v in self.look_up_table.items():
                    val.append(And(in_nib == a, out_nib == b, prob == v))
                self.solver.add(Or(*val))
                prob_terms.append(prob)

                is_active = Bool(f"active_r{r}_sbox_{i}")
                self.solver.add(is_active == (in_nib != 0))
                active_sboxes.append(is_active)

            self.active_sboxes_per_round.append(active_sboxes)
            self.solver.add(And(constraints))

            for i in range(16):
                bit = Extract(i, i, self.out_masks[r])
                self.solver.add(Extract(self.spn.pbox[i], self.spn.pbox[i], self.in_masks[r + 1]) == bit)

        total_bias = Real("total_bias")
        product_expr = reduce(lambda x, y: x * y, prob_terms)
        self.solver.add(total_bias == product_expr)
        self.solver.maximize(total_bias)

        if self.max_active_sboxes is not None:
            all_active = [b for r in self.active_sboxes_per_round for b in r]
            self.solver.add(Sum([If(b, 1, 0) for b in all_active]) <= self.max_active_sboxes)
        
        self.solver.add(self.in_masks[0] != 0)
        self.solver.add(self.in_masks[-1] != 0)

        self.prob_terms = prob_terms

    def add_mandatory_nibble(self, required_blocks: list):
        """
        Diese Methode erzwingt optional, dass bestimmte Nibbles
        in der letzten Runde aktiv sind.

        Args:
            required_blocks: Liste mit Nibble-Indizes(0-3), welche aktiv sein sollen
        """
        for i in required_blocks:
            nibble = Extract((i + 1) * 4 - 1, i * 4, self.in_masks[-1])
            self.solver.add(nibble != 0)

    def search_best_characteristic(self, num_solutions, show_results=False):
        """
        Diese Hauptmethode initialisiert den Z3-Solver und sucht eine
        beliebige Anzahl bester Charakteristiken und gibt diese als Liste
        mit Tripel, welche die Eingabemaske/Eingabedifferenz, Ausgabemaske/
        Ausgabedifferenz und den zugehörigen Bias/Wahrscheinlichkeit je nach
        Variante beinhaltet, aus.

        Args:
            num_solutions: Anzahl gewünschter Charakteristiken
            show_results: optional können Zwischenergebnisse gezeigt werden
        """
        results = []
        seen = set()

        for _ in range(num_solutions):
            if self.solver.check() != sat:
                print("Keine gültige Approximation gefunden mit den gegebenen Bedingungen.")
                break

            model = self.solver.model()
            alpha = model.evaluate(self.in_masks[0]).as_long()
            beta = model.evaluate(self.in_masks[-1]).as_long()

            if (alpha, beta) in seen:
                self.solver.add(Or(self.in_masks[0] != alpha, self.in_masks[-1] != beta))
                continue
            seen.add((alpha, beta))

            total_bias = model.evaluate(Real("total_bias"))
            bias_float = total_bias.numerator_as_long() / total_bias.denominator_as_long()
            bias_product = bias_float

            results.append((alpha, beta, bias_product))

            self.solver.add(Or(self.in_masks[0] != alpha, self.in_masks[-1] != beta))


            if show_results:
                print(f"[{_+1}] α = {alpha:04X}, β = {beta:04X}, bias_product ≈ {bias_product:.8f}")
                print("  Active bits: ")
                for r in range(self.num_rounds):
                    mask = model.evaluate(self.in_masks[r]).as_long()
                    active_bits = "".join(str((mask >> i) & 1) for i in reversed(range(16)))
                    print(f"  Round {r+1}: {active_bits}")
                out_bits = "".join(str((beta >> i) & 1) for i in reversed(range(16)))
                print(f"  Output:  {out_bits}")
                print()


        return results
