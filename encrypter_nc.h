/*
    Removing the lines of code around the header file code may cause 
    a double compilation of the header file, resulting in errors.

    Only remove if required. 
*/
#ifndef ENC_HEADER
#define ENC_HEADER

#include <stdint.h>

#define BUFFER_SIZE 4096

typedef struct lfsr128_t {
    uint64_t lfsr_h;
    // uint64_t lfsr_m;
    uint64_t lfsr_l;
} lfsr128_t;

typedef struct lfsr128x3_t {
    lfsr128_t lfsr[3];
} lfsr128x3_t;

/*      Function prototypes for initialization of LFSR seed    */
void lfsr_array_init(lfsr128x3_t *lfsr, unsigned char *password); 
void lfsr_seed_init(lfsr128_t *lfsr, unsigned char *password); 
void lfsr_array_init_from_seed(lfsr128_t *seed, lfsr128x3_t *lfsr); 
uint64_t lfsr_64_bit_val_init(lfsr128_t *lfsr, uint8_t n); 
uint64_t lfsr_shift_and_carry_bit(lfsr128_t *lfsr, int return_flag); 

/*      Function prototype for file mapper      */
int list_directory_contents(char *sDir); 

/*      Function prototypes for encryption process      */
const char *get_filename_ext(int guiFlag, lfsr128x3_t *lfsr);
void encrypt_decrypt_init(lfsr128x3_t *lfsr, char *sPath); 
void buffer_encrypter(uint8_t *buffer, lfsr128x3_t *lfsr, int size); 
uint64_t return_for_encryption(lfsr128x3_t *lfsr, uint8_t size); 
uint64_t shift_decimator(lfsr128x3_t *lfsr); 

#endif  // ENC_HEADER 
