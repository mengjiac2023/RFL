import numpy as np
from tqdm import tqdm
num_test = 10000
num_server = 15
threshold = 8

# malicious_prob = 0.1
for malicious_prob in tqdm(np.arange(0,0.5,0.05)):
    avg_iter = 0

    for _ in range(num_test):
        party_to_choose = np.arange(num_server)
        malicious_parties = np.random.choice(party_to_choose, int(num_server*malicious_prob), replace=False)
        iter = 0
        decrypt_parties = np.random.choice(party_to_choose, threshold, replace=False)

        # print(malicious_parties)
        def inclusion(array_a, array_b):
            honest_array = [x for x in array_a if x not in array_b]
            mal_array = [x for x in array_a if x in array_b]
            return honest_array,mal_array

        while True:
            honest, mal = inclusion(decrypt_parties, malicious_parties)
            if len(honest) == threshold:
                break
            party_to_choose = [x for x in party_to_choose if x not in mal and x not in honest]
            # print(party_to_choose)
            decrypt_parties = np.random.choice(party_to_choose, threshold-len(honest), replace=False)
            decrypt_parties = np.concatenate((decrypt_parties,honest))
            iter += 1
        avg_iter += iter

    print(malicious_prob,",",avg_iter/num_test)#,decrypt_parties)