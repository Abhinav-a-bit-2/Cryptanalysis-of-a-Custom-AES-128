#include <iostream>
#include <vector>
#include <iomanip>

using namespace std;

// Standard AES S-Box
const vector<uint8_t> ORIGINAL_SBOX = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const vector<uint8_t> Rcon = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// --- S-Box Generation & Key Fold ---

 vector<uint8_t> generate_dynamic_sbox(const  vector<uint8_t>& base_sbox, uint8_t dyn_key) {
     vector<int> cols = {0, 1, 2, 3, 4, 5, 6, 7};

    for (int i = 0; i < 8; i++) {
        if (dyn_key & (1 << i)) {
            int swap_idx = (i + 1) % 8;
             swap(cols[i], cols[swap_idx]);
        }
    }

     vector<uint8_t> dynamic_sbox(256);
    for (int i = 0; i < 256; i++) {
        uint8_t val = base_sbox[i];
        uint8_t new_val = 0;
        for (int j = 0; j < 8; j++) {
            uint8_t bit = (val >> cols[j]) & 1;
            new_val |= (bit << j);
        }
        dynamic_sbox[i] = new_val;
    }
    return dynamic_sbox;
}

uint8_t get_dyn_key_from_matrix(const  vector<uint8_t>& rk) {
    uint8_t dyn_key = 0;
    for (int i = 0; i < 16; i++) {
        dyn_key ^= rk[i];
    }
    return dyn_key;
}


uint8_t xtime(uint8_t a) {
    return ((a << 1) ^ (((a >> 7) & 1) * 0x1B));
}

uint8_t mul2(uint8_t x) { return xtime(x); }
uint8_t mul3(uint8_t x) { return xtime(x) ^ x; }


 vector< vector<uint8_t>> key_expansion(const  vector<uint8_t>& key) {
     vector<uint8_t> w(176);
    for (int i = 0; i < 16; i++) w[i] = key[i];

    int bytes_generated = 16;
    int rcon_iteration = 1;
     vector<uint8_t> temp(4);

    while (bytes_generated < 176) {
        for (int i = 0; i < 4; i++) temp[i] = w[bytes_generated - 4 + i];

        if (bytes_generated % 16 == 0) {
            uint8_t t = temp[0];
            temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;

            for (int i = 0; i < 4; i++) temp[i] = ORIGINAL_SBOX[temp[i]];
            
            temp[0] ^= Rcon[rcon_iteration++];
        }

        for (int i = 0; i < 4; i++) {
            w[bytes_generated] = w[bytes_generated - 16] ^ temp[i];
            bytes_generated++;
        }
    }

     vector< vector<uint8_t>> round_keys(11,  vector<uint8_t>(16));
    for (int i = 0; i < 11; i++) {
        for (int j = 0; j < 16; j++) {
            round_keys[i][j] = w[i * 16 + j];
        }
    }
    return round_keys;
}


void add_round_key( vector<uint8_t>& state, const  vector<uint8_t>& round_key) {
    for (int i = 0; i < 16; i++) state[i] ^= round_key[i];
}

void sub_bytes( vector<uint8_t>& state, const  vector<uint8_t>& sbox) {
    for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
}

void shift_rows( vector<uint8_t>& state) {
    uint8_t temp;
    // Row 1
    temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;
    // Row 2
    temp = state[2]; state[2] = state[10]; state[10] = temp;
    temp = state[6]; state[6] = state[14]; state[14] = temp;
    // Row 3
    temp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temp;
}

void mix_columns( vector<uint8_t>& state) {
    for (int c = 0; c < 4; c++) {
        uint8_t a0 = state[c * 4 + 0];
        uint8_t a1 = state[c * 4 + 1];
        uint8_t a2 = state[c * 4 + 2];
        uint8_t a3 = state[c * 4 + 3];

        state[c * 4 + 0] = mul2(a0) ^ mul3(a1) ^ a2 ^ a3;
        state[c * 4 + 1] = a0 ^ mul2(a1) ^ mul3(a2) ^ a3;
        state[c * 4 + 2] = a0 ^ a1 ^ mul2(a2) ^ mul3(a3);
        state[c * 4 + 3] = mul3(a0) ^ a1 ^ a2 ^ mul2(a3);
    }
}


 vector<uint8_t> aes_encrypt_block( vector<uint8_t> plaintext,  vector<uint8_t> key,int fault) {
    
     vector< vector<uint8_t>> round_keys = key_expansion(key);

     vector< vector<uint8_t>> round_sboxes(11);
    for (int i = 0; i <= 10; i++) {
        uint8_t rk_dyn_key = get_dyn_key_from_matrix(round_keys[i]);
        round_sboxes[i] = generate_dynamic_sbox(ORIGINAL_SBOX, rk_dyn_key);
    }

     vector<uint8_t> state = plaintext;

    // Initial Round
    add_round_key(state, round_keys[0]);

    // Rounds 1 to 9
    for (int round_num = 1; round_num <= 9; round_num++) {
        if (round_num == 8) {
            state[0] ^= fault; // Injecting a fault at 0,0 position at the input of Round 8
        } 
        sub_bytes(state, round_sboxes[round_num]);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys[round_num]);
    }

    // Final Round
    sub_bytes(state, round_sboxes[10]);
    shift_rows(state);
    add_round_key(state, round_keys[10]);

    return state;
}


int main() {
     vector<uint8_t> pt = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x35
    };
     vector<uint8_t> key = {
        0x2b, 0x7e, 0x15, 0x16, 0x18, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x12, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    //Actual Cipher - 
     vector<uint8_t> ct = aes_encrypt_block(pt, key, 0x00);
     cout << "Dynamic S-Box Actual Ciphertext: ";
    for (int i = 0; i < 16; i++) {
         cout <<  hex <<  setw(2) <<  setfill('0') << (int)ct[i];
    }
     cout << "\n";

    //faulty cipher
     vector<uint8_t> ft = aes_encrypt_block(pt, key, 0x0f);

     cout << "Dynamic S-Box Faulty Ciphertext: ";
    for (int i = 0; i < 16; i++) {
         cout <<  hex <<  setw(2) <<  setfill('0') << (int)ft[i];
    }
     cout << "\n";

    return 0;
}