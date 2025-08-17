from cryptanalysis.cryptanalysis import SPN
from cryptanalysis.cryptanalysis import FrameworkProvider
from cryptanalysis.cryptanalysis import Cryptanalysis

"""

basic execution sample

"""


def basic_execution_sample():
    sbox = [0xB, 0x1, 0xD, 0x7, 0xC, 0x9, 0x3, 0xF, 0x0, 0xA, 0x8, 0x6, 0x2, 0x5, 0x4, 0xE]
    pbox = [12, 8, 13, 9, 2, 0, 15, 5, 6, 7, 10, 14, 11, 3, 4, 1]
    round_keys = [0x1234, 0xEA5E, 0xBABE, 0xAD06, 0xCAFE]

    num_samples = 500

    spn = SPN(sbox, pbox, round_keys, rounds=4)
    framework = FrameworkProvider(spn, num_rounds_char=spn.rounds - 1, variant = 'linear', max_active_sboxes=spn.rounds - 1)
    attack = Cryptanalysis(framework)

    key = attack.find_last_round_key(num_samples)
    print(f"recovered last round key: 0x{key:04x}")