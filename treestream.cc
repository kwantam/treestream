#include <array>
#include <crypto++/sha.h>
#include <stdio.h>
#include <vector>

char dflt[] = "asdf";

uint8_t *method1(uint8_t *msg, int log_nleaves);
uint8_t *method2(uint8_t *msg, int log_nleaves);
uint8_t *method3(uint8_t *msg, int log_nleaves);
void show_hex(uint8_t *buf, int len);

int main(int argc, char **argv) {
    char *msg = dflt;
    int log_nleaves = 2;
    if (argc > 1) {
        msg = argv[1];
    }
    if (argc > 2) {
        log_nleaves = std::atoi(argv[2]);
    }

    uint8_t *digest = method1((uint8_t *)msg, log_nleaves);
    show_hex(digest, CryptoPP::SHA256::DIGESTSIZE);

    digest = method2((uint8_t *)msg, log_nleaves);
    show_hex(digest, CryptoPP::SHA256::DIGESTSIZE);

    digest = method3((uint8_t *)msg, log_nleaves);
    show_hex(digest, CryptoPP::SHA256::DIGESTSIZE);

    return 0;
}

void show_hex(uint8_t *buf, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

// naive method: store the full intermediate state of the tree
uint8_t *method1(uint8_t *msg, int log_nleaves) {
    CryptoPP::SHA256 hash;
    static uint8_t result[CryptoPP::SHA256::DIGESTSIZE];
    uint8_t *digest = (uint8_t *)calloc(CryptoPP::SHA256::DIGESTSIZE, 1 << log_nleaves);

    // initial message
    std::memset(result, 0, CryptoPP::SHA256::DIGESTSIZE);
    std::strncpy((char *)result, (char *)msg, CryptoPP::SHA256::DIGESTSIZE);

    // initialize leaves of tree
    hash.CalculateDigest(digest, result, CryptoPP::SHA256::DIGESTSIZE);
    for (int i = 1; i < (1 << log_nleaves); i++) {
        hash.CalculateDigest(digest + i * CryptoPP::SHA256::DIGESTSIZE, digest + (i-1) * CryptoPP::SHA256::DIGESTSIZE, CryptoPP::SHA256::DIGESTSIZE);
    }

    // tree computation
    for (int j = log_nleaves - 1; j >= 0; j--) {
        for (int i = 0; i < (1 << j); i++) {
            hash.CalculateDigest(result, digest + 2 * i * CryptoPP::SHA256::DIGESTSIZE, 2 * CryptoPP::SHA256::DIGESTSIZE);
            std::memcpy(digest + i * CryptoPP::SHA256::DIGESTSIZE, result, CryptoPP::SHA256::DIGESTSIZE);
        }
    }

    free(digest);
    return result;
}

// streaming method using auxiliary data structure
uint8_t *method2(uint8_t *msg, int log_nleaves) {
    CryptoPP::SHA256 hash;
    static uint8_t result[CryptoPP::SHA256::DIGESTSIZE];

    uint8_t message[CryptoPP::SHA256::DIGESTSIZE];
    uint8_t input[2 * CryptoPP::SHA256::DIGESTSIZE];
    uint8_t *input2 = input + CryptoPP::SHA256::DIGESTSIZE;

    // set up initial memory
    std::memset(message, 0, CryptoPP::SHA256::DIGESTSIZE);
    std::strncpy((char *)message, (char *)msg, CryptoPP::SHA256::DIGESTSIZE);

    // aux data structure
    std::vector<std::array<uint8_t, CryptoPP::SHA256::DIGESTSIZE>> storage(log_nleaves, {0});
    std::vector<bool> valid(log_nleaves, false);

    for (int i = 0; i < (1 << log_nleaves); i++) {
        // silly example: leaves of the tree are msg, H(msg), H(H(msg)), H(H(H(msg))), ...
        hash.CalculateDigest(message, message, CryptoPP::SHA256::DIGESTSIZE);
        std::memcpy(result, message, CryptoPP::SHA256::DIGESTSIZE);

        // the important part: walk the aux structure and update
        int j = 0;
        for (j = 0; j <= (int) valid.size() && valid[j]; j++) {
            valid[j] = false;
            std::memcpy(input, storage[j].data(), CryptoPP::SHA256::DIGESTSIZE);
            std::memcpy(input2, result, CryptoPP::SHA256::DIGESTSIZE);
            hash.CalculateDigest(result, input, 2 * CryptoPP::SHA256::DIGESTSIZE);
        }
        if (j < log_nleaves) {
            std::memcpy(storage[j].data(), result, CryptoPP::SHA256::DIGESTSIZE);
            valid[j] = true;
        }
    }

    return result;
}

// streaming method with aux data structure, written as a finite-state machine
uint8_t *method3(uint8_t *msg, int log_nleaves) {
    CryptoPP::SHA256 hash;
    static uint8_t result[CryptoPP::SHA256::DIGESTSIZE];

    uint8_t message[CryptoPP::SHA256::DIGESTSIZE];
    uint8_t input[2 * CryptoPP::SHA256::DIGESTSIZE];
    uint8_t *input2 = input + CryptoPP::SHA256::DIGESTSIZE;

    // set up initial memory
    std::memset(message, 0, CryptoPP::SHA256::DIGESTSIZE);
    std::strncpy((char *)message, (char *)msg, CryptoPP::SHA256::DIGESTSIZE);

    // aux data structure
    std::vector<std::array<uint8_t, CryptoPP::SHA256::DIGESTSIZE>> storage(log_nleaves, {0});
    std::vector<bool> valid(log_nleaves, false);

    enum class FSMState { examine_data_structure, get_next_leaf, run_hash };
    FSMState current_state = FSMState::get_next_leaf;
    int curr_slot = 0;
    int input_length = 0;

    // there are 2 * 2^log_nleaves - 1 hash invocations (run_hash state)
    // each one except the last requires a corresponding data structure access (examine_data_structure state)
    // Each leaf of the Merkle tree also requires one state machine step (get_next_leaf state)
    // in total this is 2 * (2 * 2^log_nleaves - 1) - 1 + 2^log_nleaves
    //                = (4 << log_nleaves) - 2 - 1 + (1 << log_nleaves)
    //                = (5 << log_nleaves) - 3
    for (int i = 0; i < (5 << log_nleaves) - 3; i++) {
        switch (current_state) {
        case FSMState::examine_data_structure:
            // Examine next entry of data structure; to do this without RAM, use an unrolled loop
            for (int j = 0; j < log_nleaves; j++) {
                if (j != curr_slot) {
                    continue;
                }

                if (valid[j]) {
                    // curr_slot contains an entry, so we continue hashing down the data structure
                    valid[j] = false;
                    std::memcpy(input, storage[j].data(), CryptoPP::SHA256::DIGESTSIZE);
                    std::memcpy(input2, result, CryptoPP::SHA256::DIGESTSIZE);
                    input_length = 2 * CryptoPP::SHA256::DIGESTSIZE;
                    current_state = FSMState::run_hash;
                } else {
                    // curr_slot contains no entry, so store result here and grab a new leaf (below)
                    valid[j] = true;
                    std::memcpy(storage[j].data(), result, CryptoPP::SHA256::DIGESTSIZE);
                    curr_slot = -1;
                    current_state = FSMState::get_next_leaf;
                }
            }

            curr_slot++;
            break; // case FSMState::examine_data_structure

        case FSMState::get_next_leaf:
            // get next leaf of Merkle tree
            std::memcpy(input, message, CryptoPP::SHA256::DIGESTSIZE);
            input_length = CryptoPP::SHA256::DIGESTSIZE;
            current_state = FSMState::run_hash;

            // silly example: leaves of the tree are msg, H(msg), H(H(msg)), H(H(H(msg))), ...
            // calculate the next leaf now in preparation for next pass through this state
            hash.CalculateDigest(message, message, CryptoPP::SHA256::DIGESTSIZE);

            break; // case FSMState::get_next_leaf

        case FSMState::run_hash:
            // this state: invoke SHA
            hash.CalculateDigest(result, input, input_length);
            current_state = FSMState::examine_data_structure;

            break; // case FSMState::run_hash

        default:
            printf("ERROR invalid state\n");
            std::exit(-1);
        }
    }

    return result;
}
