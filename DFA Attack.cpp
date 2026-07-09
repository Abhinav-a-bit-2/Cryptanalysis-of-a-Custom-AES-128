#include <iostream>
#include <vector>
#include <array>
#include <string>
#include <iomanip>
#include <chrono>
#include <omp.h>

using namespace std;

using block_t = array<uint8_t, 16>;
using state_t = array<array<uint8_t, 4>, 4>;

// Standard AES S-Box
const array<uint8_t, 256> ORIGINAL_SBOX = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
const array<uint8_t, 11> Rcon = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};

// Standard MixColumns Matrix
const uint8_t MC_MAT[4][4] = {
    {2, 3, 1, 1},
    {1, 2, 3, 1},
    {1, 1, 2, 3},
    {3, 1, 1, 2}
};

// Global S-Box Caches
array<array<uint8_t, 256>, 256> SBOX_CACHE;
array<array<uint8_t, 256>, 256> INV_SBOX_CACHE;

// ShiftRow Mapping (used to index CT bytes back to columns)
const int COL_IDX[4][4] = {{0, 13, 10, 7}, {4, 1, 14, 11}, {8, 5, 2, 15}, {12, 9, 6, 3}};

inline uint8_t xtime(uint8_t a) { return (a << 1) ^ ((a & 0x80) ? 0x1B : 0x00); }

inline uint8_t mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i=0; i<8; i++) { if (a & 1) p ^= b; bool hi = (b & 0x80); b <<= 1; if (hi) b ^= 0x1B; a >>= 1; } return p;
}

uint8_t get_dyn_key(const block_t& k){ 
    uint8_t s = 0;
    for(auto b : k) s ^= b;
    return s; }
    
block_t hex_to_bytes(const string& hex){ 
    block_t b;
    for(unsigned int i=0; i<hex.length(); i+=2) b[i/2] = strtol(hex.substr(i,2).c_str(), nullptr, 16);
    return b; }
    
string bytes_to_hex(const block_t& b){ 
    string h="";
    const char c[]="0123456789abcdef";
    for(auto v:b){
    h+=c[v>>4];
    h+=c[v&0x0F];
}
    return h;
}

state_t bytes_to_state(const block_t& b){
    state_t s;
    for(int i=0; i<16; i++) s[i%4][i/4] = b[i];
    return s; }


void init_sboxes() {
    for (int dk = 0; dk < 256; dk++) {
        array<int, 8> cols = {0,1,2,3,4,5,6,7};
        for (int i=0; i<8; i++) if (dk & (1<<i)) swap(cols[i], cols[(i+1)%8]);
        for (int val = 0; val < 256; val++) {
            uint8_t new_val = 0, orig = ORIGINAL_SBOX[val];
            for (int i=0; i<8; i++) new_val |= (((orig >> cols[i]) & 1) << i);
            SBOX_CACHE[dk][val] = new_val;
            INV_SBOX_CACHE[dk][new_val] = val;
        }
    }
}

// --- STATE REVERSAL FUNCTIONS ---
void inv_shift_rows(state_t& st) {
    state_t r = st;
    r[1][0]=st[1][3]; r[1][1]=st[1][0]; r[1][2]=st[1][1]; r[1][3]=st[1][2];
    r[2][0]=st[2][2]; r[2][1]=st[2][3]; r[2][2]=st[2][0]; r[2][3]=st[2][1];
    r[3][0]=st[3][1]; r[3][1]=st[3][2]; r[3][2]=st[3][3]; r[3][3]=st[3][0];
    st = r;
}

void inv_mix_columns(state_t& st) {
    state_t r;
    for (int c=0; c<4; c++) {
        r[0][c] = mul(14,st[0][c]) ^ mul(11,st[1][c]) ^ mul(13,st[2][c]) ^ mul(9,st[3][c]);
        r[1][c] = mul(9,st[0][c]) ^ mul(14,st[1][c]) ^ mul(11,st[2][c]) ^ mul(13,st[3][c]);
        r[2][c] = mul(13,st[0][c]) ^ mul(9,st[1][c]) ^ mul(14,st[2][c]) ^ mul(11,st[3][c]);
        r[3][c] = mul(11,st[0][c]) ^ mul(13,st[1][c]) ^ mul(9,st[2][c]) ^ mul(14,st[3][c]);
    }
    st = r;
}

// --- KEY SCHEDULE MATH ---
block_t get_k9_from_k10(const block_t& k10) {
    block_t k9; uint32_t w10[4], w9[4];
    for(int i=0; i<4; i++) w10[i] = (k10[i*4]<<24)|(k10[i*4+1]<<16)|(k10[i*4+2]<<8)|k10[i*4+3];
    w9[3] = w10[3]^w10[2]; w9[2] = w10[2]^w10[1]; w9[1] = w10[1]^w10[0];
    uint32_t t = w9[3]; t = (t<<8)|(t>>24);
    uint32_t sub = (ORIGINAL_SBOX[t>>24]<<24)|(ORIGINAL_SBOX[(t>>16)&0xFF]<<16)|(ORIGINAL_SBOX[(t>>8)&0xFF]<<8)|ORIGINAL_SBOX[t&0xFF];
    sub ^= 0x36000000; w9[0] = w10[0]^sub;
    for(int i=0; i<4; i++) { k9[i*4]=w9[i]>>24; k9[i*4+1]=(w9[i]>>16)&0xFF; k9[i*4+2]=(w9[i]>>8)&0xFF; k9[i*4+3]=w9[i]&0xFF; }
    return k9;
}

block_t reverse_to_master_key(const block_t& k10) {
    block_t current_k = k10;
    for(int r=10; r>0; r--) {
        uint32_t w[4], p[4];
        for(int i=0; i<4; i++) w[i] = (current_k[i*4]<<24)|(current_k[i*4+1]<<16)|(current_k[i*4+2]<<8)|current_k[i*4+3];
        p[3] = w[3]^w[2]; p[2] = w[2]^w[1]; p[1] = w[1]^w[0];
        uint32_t t = p[3]; t = (t<<8)|(t>>24);
        uint32_t sub = (ORIGINAL_SBOX[t>>24]<<24)|(ORIGINAL_SBOX[(t>>16)&0xFF]<<16)|(ORIGINAL_SBOX[(t>>8)&0xFF]<<8)|ORIGINAL_SBOX[t&0xFF];
        sub ^= (Rcon[r]<<24); p[0] = w[0]^sub;
        for(int i=0; i<4; i++) {
        current_k[i*4]=p[i]>>24;
        current_k[i*4+1]=(p[i]>>16)&0xFF;
        current_k[i*4+2]=(p[i]>>8)&0xFF;
        current_k[i*4+3]=p[i]&0xFF; }
    }
    return current_k;
}

bool verify_key_loophole(const block_t& candidate_k10, const block_t& pt, const block_t& known_ct) {
    block_t master_key = reverse_to_master_key(candidate_k10);
    
    block_t current_k = master_key;
    state_t st = bytes_to_state(pt);
    
    // AddRoundKey 0
    for(int r=0; r<4; r++) for(int c=0; c<4; c++) st[r][c] ^= current_k[c*4+r];

    // Rounds 1-9
    for(int rnd=1; rnd<=9; rnd++) {
        // Expand next key

        uint32_t w[4]; for(int i=0; i<4; i++) w[i] = (current_k[i*4]<<24)|(current_k[i*4+1]<<16)|(current_k[i*4+2]<<8)|current_k[i*4+3];
        uint32_t t = w[3]; t = (t<<8)|(t>>24);
        uint32_t sub = (ORIGINAL_SBOX[t>>24]<<24)|(ORIGINAL_SBOX[(t>>16)&0xFF]<<16)|(ORIGINAL_SBOX[(t>>8)&0xFF]<<8)|ORIGINAL_SBOX[t&0xFF];
        w[0] ^= sub ^ (Rcon[rnd]<<24); w[1] ^= w[0]; w[2] ^= w[1]; w[3] ^= w[2];
        for(int i=0; i<4; i++) {
            current_k[i*4]=w[i]>>24;
            current_k[i*4+1]=(w[i]>>16)&0xFF;
            current_k[i*4+2]=(w[i]>>8)&0xFF;
            current_k[i*4+3]=w[i]&0xFF; 
        }
        
        uint8_t dk = get_dyn_key(current_k);
        for(int r=0; r<4; r++) for(int c=0; c<4; c++) st[r][c] = SBOX_CACHE[dk][st[r][c]];
        state_t temp = st;
        st[1][0]=temp[1][1]; st[1][1]=temp[1][2]; st[1][2]=temp[1][3]; st[1][3]=temp[1][0];
        st[2][0]=temp[2][2]; st[2][1]=temp[2][3]; st[2][2]=temp[2][0]; st[2][3]=temp[2][1];
        st[3][0]=temp[3][3]; st[3][1]=temp[3][0]; st[3][2]=temp[3][1]; st[3][3]=temp[3][2];
        
        state_t r_mc;
        for (int c=0; c<4; c++) {
            r_mc[0][c] = mul(2,st[0][c]) ^ mul(3,st[1][c]) ^ st[2][c] ^ st[3][c];
            r_mc[1][c] = st[0][c] ^ mul(2,st[1][c]) ^ mul(3,st[2][c]) ^ st[3][c];
            r_mc[2][c] = st[0][c] ^ st[1][c] ^ mul(2,st[2][c]) ^ mul(3,st[3][c]);
            r_mc[3][c] = mul(3,st[0][c]) ^ st[1][c] ^ st[2][c] ^ mul(2,st[3][c]);
        }
        st = r_mc;
        for(int r=0; r<4; r++) for(int c=0; c<4; c++) st[r][c] ^= current_k[c*4+r];
    }
    
    // Round 10
    uint32_t w[4]; for(int i=0; i<4; i++) w[i] = (current_k[i*4]<<24)|(current_k[i*4+1]<<16)|(current_k[i*4+2]<<8)|current_k[i*4+3];
    uint32_t t = w[3]; t = (t<<8)|(t>>24);
    uint32_t sub = (ORIGINAL_SBOX[t>>24]<<24)|(ORIGINAL_SBOX[(t>>16)&0xFF]<<16)|(ORIGINAL_SBOX[(t>>8)&0xFF]<<8)|ORIGINAL_SBOX[t&0xFF];
    w[0] ^= sub ^ (Rcon[10]<<24); w[1] ^= w[0]; w[2] ^= w[1]; w[3] ^= w[2];
    for(int i=0; i<4; i++) {
        current_k[i*4]=w[i]>>24;
        current_k[i*4+1]=(w[i]>>16)&0xFF;
        current_k[i*4+2]=(w[i]>>8)&0xFF;
        current_k[i*4+3]=w[i]&0xFF; 
    }
    
    uint8_t dk10 = get_dyn_key(current_k);
    for(int r=0; r<4; r++) for(int c=0; c<4; c++) st[r][c] = SBOX_CACHE[dk10][st[r][c]];
    state_t temp = st;
    st[1][0]=temp[1][1]; st[1][1]=temp[1][2]; st[1][2]=temp[1][3]; st[1][3]=temp[1][0];
    st[2][0]=temp[2][2]; st[2][1]=temp[2][3]; st[2][2]=temp[2][0]; st[2][3]=temp[2][1];
    st[3][0]=temp[3][3]; st[3][1]=temp[3][0]; st[3][2]=temp[3][1]; st[3][3]=temp[3][2];
    for(int r=0; r<4; r++) for(int c=0; c<4; c++) st[r][c] ^= current_k[c*4+r];

    // Check CT
    block_t generated_ct;
    for(int i=0; i<16; i++) generated_ct[i] = st[i%4][i/4];
    
    return generated_ct == known_ct;
}

// STEP 2:
bool evaluate_step2(const block_t& k10, const block_t& ct, const block_t& ft) {
    block_t k9 = get_k9_from_k10(k10);
    uint8_t dk10 = get_dyn_key(k10);
    uint8_t dk9 = get_dyn_key(k9);

    state_t st_c = bytes_to_state(ct);
    state_t st_f = bytes_to_state(ft);

    //  Reverse R10 AddRoundKey
    for(int r=0; r<4; r++) for(int c=0; c<4; c++) { st_c[r][c] ^= k10[c*4+r]; st_f[r][c] ^= k10[c*4+r]; }
    
    // Reverse R10 ShiftRows & SubBytes
    inv_shift_rows(st_c); inv_shift_rows(st_f);
    for(int r=0; r<4; r++) for(int c=0; c<4; c++) {
        st_c[r][c] = INV_SBOX_CACHE[dk10][st_c[r][c]];
        st_f[r][c] = INV_SBOX_CACHE[dk10][st_f[r][c]];
        }

    // Reverse R9 AddRoundKey
    for(int r=0; r<4; r++) for(int c=0; c<4; c++) {
        st_c[r][c] ^= k9[c*4+r]; 
        st_f[r][c] ^= k9[c*4+r]; 
        }

    // Reverse R9 MixColumns & ShiftRows
    inv_mix_columns(st_c); inv_mix_columns(st_f);
    inv_shift_rows(st_c); inv_shift_rows(st_f);

    // Reverse R9 SubBytes 
    for(int r=0; r<4; r++) for(int c=0; c<4; c++) {
        st_c[r][c] = INV_SBOX_CACHE[dk9][st_c[r][c]]; 
        st_f[r][c] = INV_SBOX_CACHE[dk9][st_f[r][c]]; 
        }

    //  STATE BEFORE R9 SUBBYTES 
    
    //  Cols 1, 2, and 3 are zero difference
    for (int c = 1; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            if (st_c[r][c] != st_f[r][c]) return false;
        }
    }

    // Check ratio (2f', f', f', 3f') in Col 0
    uint8_t d0 = st_c[0][0] ^ st_f[0][0];
    uint8_t d1 = st_c[1][0] ^ st_f[1][0];
    uint8_t d2 = st_c[2][0] ^ st_f[2][0];
    uint8_t d3 = st_c[3][0] ^ st_f[3][0];

    if (d1 == 0) return false;
    if (d0 != mul(2, d1)) return false;
    if (d2 != d1) return false;
    if (d3 != mul(3, d1)) return false;

    return true;
}


int main() {
block_t pt = hex_to_bytes("3243f6a8885a308d313198a2e0370735");
    block_t ct = hex_to_bytes("0e336bdf3297245b66f1c69570b78180"); 
    block_t ft = hex_to_bytes("2d62ec68882c7fc2823fe87a990e09f4");
    // actual key - 2b7e151618aed2a6abf7128809cf4f3c
    cout << "[INFO] Commencing Dynamic AES-128 DFA Solver..." << endl;
    cout << "[INFO] Generating S-Box Caches..." << endl;
    init_sboxes();

    volatile bool global_found = false;
    block_t final_k10;
    block_t final_master_key;

    auto t0 = chrono::high_resolution_clock::now();

    #pragma omp parallel for schedule(dynamic)
    for (int dk10 = 0; dk10 < 256; dk10++) {
        if (global_found) continue;

        const auto& invS = INV_SBOX_CACHE[dk10];
        vector<array<uint8_t, 4>> quartets[4];

        // STEP 1
        bool valid_topology = true;
        for (int col = 0; col < 4; col++) {
            // Apply the inverse ShiftRows offset to match the fault ratio to the correct column
            int r_c = (4 - col) % 4; 
            
            for (int delta = 1; delta < 256; delta++) {
                // Dynamically fetch the multiplier ratio from the MixColumns Matrix based on the shifted row
                uint8_t e[4] = {
                    mul(MC_MAT[0][r_c], delta), 
                    mul(MC_MAT[1][r_c], delta), 
                    mul(MC_MAT[2][r_c], delta), 
                    mul(MC_MAT[3][r_c], delta)
                };
                
                vector<uint8_t> k_cands[4];
                
                for (int row = 0; row < 4; row++) {
                    int idx = COL_IDX[col][row];
                    for (int k = 0; k < 256; k++) {
                        if ((invS[ct[idx] ^ k] ^ invS[ft[idx] ^ k]) == e[row]) k_cands[row].push_back(k);
                    }
                }
                for (uint8_t k0 : k_cands[0]) for (uint8_t k1 : k_cands[1]) for (uint8_t k2 : k_cands[2]) for (uint8_t k3 : k_cands[3]) {
                    quartets[col].push_back({k0, k1, k2, k3});
                }
            }
            if (quartets[col].empty()) { valid_topology = false; break; }
        }

        if (!valid_topology) continue;

        // Assemble K10 candidates
        for (const auto& q0 : quartets[0]) {
            if (global_found) break;
            for (const auto& q1 : quartets[1]) {
                if (global_found) break;
                for (const auto& q2 : quartets[2]) {
                    if (global_found) break;
                    
                    uint8_t partial_sum = q0[0]^q0[1]^q0[2]^q0[3] ^ q1[0]^q1[1]^q1[2]^q1[3] ^ q2[0]^q2[1]^q2[2]^q2[3];

                    for (const auto& q3 : quartets[3]) {
                        if ((partial_sum ^ q3[0]^q3[1]^q3[2]^q3[3]) == dk10) {
                            
                            block_t cand_k10;
                            cand_k10[0]=q0[0]; cand_k10[13]=q0[1]; cand_k10[10]=q0[2]; cand_k10[7]=q0[3];
                            cand_k10[4]=q1[0]; cand_k10[1]=q1[1];  cand_k10[14]=q1[2]; cand_k10[11]=q1[3];
                            cand_k10[8]=q2[0]; cand_k10[5]=q2[1];  cand_k10[2]=q2[2];  cand_k10[15]=q2[3];
                            cand_k10[12]=q3[0];cand_k10[9]=q3[1];  cand_k10[6]=q3[2];  cand_k10[3]=q3[3];

                            //STEP 2
                            if (evaluate_step2(cand_k10, ct, ft)) {
                                #pragma omp critical
                                cout << "[STEP 2] K10 Candidate passed Reverse Sieve constraint check." << endl;
                                
                                if (verify_key_loophole(cand_k10, pt, ct)) {
                                    #pragma omp critical
                                    {
                                        if (!global_found) {
                                            cout << "[VERIFY] Loophole check passed! Forward encryption matches known CT." << endl;
                                            global_found = true;
                                            final_k10 = cand_k10;
                                            final_master_key = reverse_to_master_key(cand_k10);
                                        }
                                    }
                                } else {
                                    #pragma omp critical
                                    cout << "[VERIFY] False positive detected by loophole! Discarding candidate." << endl;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (global_found) {
        cout << "\n[SUCCESS] Master Key Recovered: " << bytes_to_hex(final_master_key) << endl;
    } else {
        cout << "\n[FAILED] Exhausted all possibilities. No key found." << endl;
    }

    return 0;
}