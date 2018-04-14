#include <array>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <crypto++/modes.h>
#include <crypto++/osrng.h>
#include <crypto++/sha.h>
#include <vector>

using namespace CryptoPP;

uint8_t *method1(const uint8_t *seed, int log_nleaves);
uint8_t *method2(const uint8_t *seed, int log_nleaves);
uint8_t *method3(const uint8_t *seed, int log_nleaves);

int main(int argc, char **argv) {
    int log_nleaves = 2;
    uint8_t *digest = nullptr;
    if (argc > 1) {
        log_nleaves = std::atoi(argv[1]);
    }

    // random seed for generating leaves of tree
    uint8_t seed[AES::MAX_KEYLENGTH + AES::BLOCKSIZE];
    OS_GenerateRandomBlock(false, seed, sizeof(seed));

    for (auto &method : {method1, method2, method3}) {
        digest = method(seed, log_nleaves);
        for (int i = 0; i < SHA256::DIGESTSIZE; i++) {
            std::printf("%02x", digest[i]);
        }
        std::printf("\n");
    }

    return 0;
}

// naive method: store the full intermediate state of the tree
uint8_t *method1(const uint8_t *seed, int log_nleaves) {
    SHA256 hash;
    static uint8_t result[SHA256::DIGESTSIZE];
    uint8_t *digest = (uint8_t *)calloc(SHA256::DIGESTSIZE, 2 << log_nleaves);

    // RNG for leaves of tree
    CTR_Mode<AES>::Encryption prg;
    prg.SetKeyWithIV(seed, AES::MAX_KEYLENGTH, seed + AES::MAX_KEYLENGTH, AES::BLOCKSIZE);

    // initialize leaves of tree
    const int outblocksize = sizeof(result);
    const int inblocksize = 2 * outblocksize;
    for (int i = 0; i < (1 << log_nleaves); i++) {
        prg.GenerateBlock(digest + i * inblocksize, inblocksize);
    }

    // compute tree
    for (int j = log_nleaves; j >= 0; j--) {
        for (int i = 0; i < (1 << j); i++) {
            hash.CalculateDigest(digest + i * outblocksize, digest + i * inblocksize, inblocksize);
        }
    }

    std::memcpy(result, digest, sizeof(result));
    free(digest);
    return result;
}

// streaming method using auxiliary data structure
uint8_t *method2(const uint8_t *seed, int log_nleaves) {
    SHA256 hash;
    static uint8_t result[SHA256::DIGESTSIZE];
    uint8_t input[2 * SHA256::DIGESTSIZE];
    uint8_t *input2 = input + SHA256::DIGESTSIZE;
    static_assert(sizeof(input) == 2 * sizeof(result), "ERROR inconsistent hash input/output sizing");

    // aux data structure
    std::vector<std::array<uint8_t, SHA256::DIGESTSIZE>> storage(log_nleaves, {0});
    std::vector<bool> valid(log_nleaves, false);
    static_assert(sizeof(result) == sizeof(storage[0]), "ERROR inconsistent sizing in aux data structure");

    // RNG for leaves of tree
    CTR_Mode<AES>::Encryption prg;
    prg.SetKeyWithIV(seed, AES::MAX_KEYLENGTH, seed + AES::MAX_KEYLENGTH, AES::BLOCKSIZE);

    for (int i = 0; i < (1 << log_nleaves); i++) {
        // next leaf of tree
        prg.GenerateBlock(input, sizeof(input));
        hash.CalculateDigest(result, input, sizeof(input));

        // the important part: walk the aux structure and update
        int j = 0;
        for (j = 0; j <= (int) valid.size() && valid[j]; j++) {
            valid[j] = false;
            std::memcpy(input, storage[j].data(), sizeof(result));
            std::memcpy(input2, result, sizeof(result));
            hash.CalculateDigest(result, input, sizeof(input));
        }
        if (j < log_nleaves) {
            std::memcpy(storage[j].data(), result, sizeof(result));
            valid[j] = true;
        }
    }

    return result;
}

// streaming method with aux data structure, written as a finite-state machine
uint8_t *method3(const uint8_t *seed, int log_nleaves) {
    SHA256 hash;
    static uint8_t result[SHA256::DIGESTSIZE];
    uint8_t input[2 * SHA256::DIGESTSIZE];
    uint8_t *input2 = input + SHA256::DIGESTSIZE;
    static_assert(sizeof(input) == 2 * sizeof(result), "ERROR inconsistent hash input/output sizing");

    // aux data structure
    std::vector<std::array<uint8_t, SHA256::DIGESTSIZE>> storage(log_nleaves, {0});
    std::vector<bool> valid(log_nleaves, false);
    static_assert(sizeof(result) == sizeof(storage[0]), "ERROR inconsistent sizing in aux data structure");

    // RNG for leaves of tree
    CTR_Mode<AES>::Encryption prg;
    prg.SetKeyWithIV(seed, AES::MAX_KEYLENGTH, seed + AES::MAX_KEYLENGTH, AES::BLOCKSIZE);

    // finite state machine
    enum class FSMState { access_data_structure, get_next_leaf, run_hash };
    FSMState current_state = FSMState::get_next_leaf;
    int current_slot = 0;

    // there are 2 * 2^log_nleaves - 1 hash invocations (run_hash state)
    // each one except the last requires a corresponding data structure access (access_data_structure state)
    // Each leaf of the Merkle tree also requires one state machine step (get_next_leaf state)
    // in total this is 2 * (2 * 2^log_nleaves - 1) - 1 + 2^log_nleaves
    //                = (4 << log_nleaves) - 2 - 1 + (1 << log_nleaves)
    //                = (5 << log_nleaves) - 3
    for (int i = 0; i < (5 << log_nleaves) - 3; i++) {
        switch (current_state) {
        case FSMState::access_data_structure:
            // Examine next entry of data structure; to do this with fixed RAM access pattern, use a loop
            for (int j = 0; j < log_nleaves; j++) {
                if (j == current_slot) {
                    if (valid[j]) {
                        // current_slot contains an entry, so we continue hashing down the data structure
                        valid[j] = false;
                        std::memcpy(input, storage[j].data(), sizeof(result));
                        std::memcpy(input2, result, sizeof(result));
                        // danger: don't update current_slot inside the loop!
                        current_state = FSMState::run_hash;
                    } else {
                        // current_slot contains no entry, so store result here and grab the next leaf
                        valid[j] = true;
                        std::memcpy(storage[j].data(), result, sizeof(result));
                        current_state = FSMState::get_next_leaf;
                    }
                }
            }

            current_slot++; // update current slot
            break; // case FSMState::access_data_structure

        case FSMState::get_next_leaf:
            // get next leaf of Merkle tree
            prg.GenerateBlock(input, sizeof(input));
            current_slot = 0;
            current_state = FSMState::run_hash;

            break; // case FSMState::get_next_leaf

        case FSMState::run_hash:
            // this state: invoke SHA
            hash.CalculateDigest(result, input, sizeof(input));
            current_state = FSMState::access_data_structure;

            break; // case FSMState::run_hash

        default:
            printf("ERROR invalid state\n");
            std::exit(-1);
        }
    }

    return result;
}
