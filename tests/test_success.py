import time
from spn.spn import SPN
from cryptanalysis.framework import FrameworkProvider
from cryptanalysis.cryptanalysis import Cryptanalysis
from multiprocessing import Pool, cpu_count
import matplotlib.pyplot as plt
import numpy as np


class SuccessVsSamples:
    def _run_single_attack(self, args):
        num_samples, attack, true_key = args
        start = time.time()
        guessed_key = attack.find_last_round_key(num_samples)
        end = time.time()
        success = guessed_key == true_key
        return (success, end - start)

    def analyse_success_rate(self, repeats, sample_steps):
        sbox = [0xB, 0x1, 0xD, 0x7, 0xC, 0x9, 0x3, 0xF, 0x0, 0xA, 0x8, 0x6, 0x2, 0x5, 0x4, 0xE]
        pbox = [12, 8, 13, 9, 2, 0, 15, 5, 6, 7, 10, 14, 11, 3, 4, 1]
        round_keys = [0x1234, 0xEA5E, 0xBABE, 0xAD06, 0xCAFE]

        true_key = round_keys[4]

        results_plot = {
            'differential': {'samples': [], 'success_rates': [], 'avg_times': []},
            'linear': {'samples': [], 'success_rates': [], 'avg_times': []}
        }

        for variant in ['linear', 'differential']:
            print(f"attack variant: {variant.upper()}")

            spn = SPN(sbox, pbox, round_keys, rounds=4)
            framework = FrameworkProvider(spn, num_rounds_char=3, variant=variant, max_active_sboxes=3)
            attack = Cryptanalysis(framework)

            for i in sample_steps:
                args = [(i, attack, true_key)] * repeats

                with Pool(processes=cpu_count()) as pool:
                    results = pool.map(self._run_single_attack, args)

                correct_count = sum(1 for success, _ in results if success)
                total_time = sum(duration for _, duration in results)

                avg_time = total_time / repeats
                success_rate = (correct_count / repeats) * 100

                print(f"{variant.upper()}; Samples: {i}, Success: {success_rate:.1f}%, Time: {avg_time:.2f}s")

                results_plot[variant]['samples'].append(i)
                results_plot[variant]['success_rates'].append(success_rate)
                results_plot[variant]['avg_times'].append(avg_time)

        fig1, ax1 = plt.subplots(figsize=(10, 6))
        ax1.set_xlabel('Anzahl Textpaare')
        ax1.set_ylabel('Erfolgsrate (%)')
        ax1.scatter(results_plot['linear']['samples'], results_plot['linear']['success_rates'],
                    color='blue', label='Erfolgsrate (Linear)', alpha=0.3)
        ax1.scatter(results_plot['differential']['samples'], results_plot['differential']['success_rates'],
                    color='purple', label='Erfolgsrate (Differentiell)', alpha=0.3)
        ax1.grid(True)
        ax1.legend(loc='upper left')
        plt.title('Erfolgsrate in Abhängigkeit der Anzahl Textpaare')
        plt.tight_layout()
        plt.savefig("samples_1.png", dpi=300)
        plt.show()

        fig2, ax2 = plt.subplots(figsize=(10, 6))
        ax2.set_xlabel('Anzahl Textpaare')
        ax2.set_ylabel('Durchschnittliche Angriffszeit (s)')
        ax2.grid(True)

        for data_key, color, label in [
            ('linear', 'red', '(Linear)'),
            ('differential', 'darkred', '(Differentiell)')
        ]:
            x = np.array(results_plot[data_key]['samples'])
            y = np.array(results_plot[data_key]['avg_times'])

            ax2.scatter(x, y, color=color, alpha=0.3, label=f'Durchschnittliche Laufzeit{label}')

            coeffs = np.polyfit(x, y, deg=1)
            trend = np.poly1d(coeffs)
            ax2.plot(x, trend(x), color=color, linewidth=2.0, label=f'Trend {label}')

        ax2.legend(loc='upper left')
        plt.title('Durchschnittliche Laufzeiten')
        plt.tight_layout()
        plt.savefig("time_1.png", dpi=300)
        plt.show()


if __name__ == '__main__':
    test_3 = SuccessVsSamples()
    test_3.analyse_success_rate(50, [1] + list(range(3,298, 3)) + list(range(300, 551, 5)))