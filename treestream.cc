#include <array>
#include <crypto++/sha.h>
#include <stdio.h>
#include <vector>

char dflt[] = "asdf";

uint8_t *method1(uint8_t *msg, int log_nleaves);
uint8_t *method2(uint8_t *msg, int log_nleaves);
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

    return 0;
}

void show_hex(uint8_t *buf, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

// streaming method using auxiliary data structure
uint8_t *method2(uint8_t *msg, int log_nleaves) {
    CryptoPP::SHA256 hash;
    static uint8_t result[CryptoPP::SHA256::DIGESTSIZE];

    uint8_t message[CryptoPP::SHA256::DIGESTSIZE];
    uint8_t input[2 * CryptoPP::SHA256::DIGESTSIZE];
    uint8_t *input2 = input + CryptoPP::SHA256::DIGESTSIZE;

    // aux data structure
    std::vector<std::array<uint8_t, CryptoPP::SHA256::DIGESTSIZE>> storage(log_nleaves, {0});
    std::vector<bool> valid(log_nleaves, false);

    for (int i = 0; i < (1 << log_nleaves); i++) {
        // silly example: leaves of the tree are msg, H(msg), H(H(msg)), H(H(H(msg))), ...
        if (i == 0) {
            hash.CalculateDigest(result, msg, std::strlen((char *)msg));
        } else {
            hash.CalculateDigest(result, message, CryptoPP::SHA256::DIGESTSIZE);
        }
        std::memcpy(message, result, CryptoPP::SHA256::DIGESTSIZE);

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

// naive method: store the full intermediate state of the tree
uint8_t *method1(uint8_t *msg, int log_nleaves) {
    CryptoPP::SHA256 hash;
    static uint8_t result[CryptoPP::SHA256::DIGESTSIZE];
    uint8_t *digest = (uint8_t *)calloc(CryptoPP::SHA256::DIGESTSIZE, 1 << log_nleaves);

    // initialize leaves of tree
    hash.CalculateDigest(digest, msg, std::strlen((char *)msg));
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
