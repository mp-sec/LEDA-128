/*
    Compile program using: 
        gcc encrypter.c sha256.c -o [outputFileName.exe] 
    The above is required to compile this file, both encrypter.c, and the 
    required sha256.c file for initializing the seed LFRS. 

    Running the compiled file requires the following in the CMD: 
        [filename].exe [password] [0 for decrypt or 1 for encrypt]
    This program will run over a folder named SecureFolder that is in the
    same directory as the compiled and run executable. 
*/

#include <stdio.h>
#include <string.h>
// #include <time.h>    // Uncomment for timer functionality in main() 
#include <dirent.h>     // Required for file mapping 
#include <fileapi.h>    // Required for hiding a folder 
#include <windows.h>    // Required for file mapping 
// #include <pthread.h>    // Required for multithreading 
/*
    This header is only for printing uint64_t integers. An example format for 
    printing these numbers is: 
        printf("\t%"PRIu64"\n", lfsr_h);
    
    #include <inttypes.h> 
*/

/*
    These are required for program functionality. Do not remove them. 
*/
#include "encrypter_nc.h"
#include "sha256.h"


/***********     BEGINNING OF INITIALIZATION     **********/ 

void lfsr_array_init(lfsr128x3_t *lfsr, unsigned char *password) {
    lfsr128_t lfsr_seed;

    lfsr_seed_init(&lfsr_seed, password);
    lfsr_array_init_from_seed(&lfsr_seed, lfsr);
}

void lfsr_seed_init(lfsr128_t *lfsr, unsigned char *password) {
    BYTE hash_buffer[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;

    uint64_t lfsr_h;
    uint64_t lfsr_l;

    sha256_init(&ctx);
    sha256_update(&ctx, password, strlen((char *) password));
    sha256_final(&ctx, hash_buffer);

    memcpy(&lfsr_h, hash_buffer, sizeof(uint64_t));
    memcpy(&lfsr_l, hash_buffer + sizeof(uint64_t), sizeof(uint64_t));

    lfsr->lfsr_h = lfsr_h;
    lfsr->lfsr_l = lfsr_l;
}

void lfsr_array_init_from_seed(lfsr128_t *seed, lfsr128x3_t *lfsr) {
  lfsr->lfsr[0].lfsr_h = lfsr_64_bit_val_init(seed, 64);
  // lfsr->lfsr[0].lfsr_m = lfsr_64_bit_val_init(seed, 64);
  lfsr->lfsr[0].lfsr_l = lfsr_64_bit_val_init(seed, 64);
  lfsr->lfsr[1].lfsr_h = lfsr_64_bit_val_init(seed, 64);
  // lfsr->lfsr[1].lfsr_m = lfsr_64_bit_val_init(seed, 64);
  lfsr->lfsr[1].lfsr_l = lfsr_64_bit_val_init(seed, 64);
  lfsr->lfsr[2].lfsr_h = lfsr_64_bit_val_init(seed, 64);
  // lfsr->lfsr[2].lfsr_m = lfsr_64_bit_val_init(seed, 64);
  lfsr->lfsr[2].lfsr_l = lfsr_64_bit_val_init(seed, 64);
}

uint64_t lfsr_64_bit_val_init(lfsr128_t *lfsr, uint8_t n) {

    uint64_t initialized_val = 0; 
    int return_flag = 1; 
    int i;

    initialized_val = lfsr_shift_and_carry_bit(lfsr, return_flag);

    for (i = 0; i < n - 1; i++) {
       initialized_val = initialized_val << 1;
       initialized_val = initialized_val | lfsr_shift_and_carry_bit(lfsr, return_flag);
    }

    return initialized_val;
}

uint64_t lfsr_shift_and_carry_bit(lfsr128_t *lfsr, int return_flag) {
  uint64_t bit_l, bit_h, shifted_bit;

    shifted_bit = lfsr->lfsr_l & 1;

    bit_l = ((lfsr->lfsr_l >> 0) ^ (lfsr->lfsr_l >> 1) ^ (lfsr->lfsr_l >> 2) ^
            (lfsr->lfsr_l >> 7)) & 1;
    bit_h = lfsr->lfsr_h & 1;

    lfsr->lfsr_l = (lfsr->lfsr_l >> 1) | (bit_h << 63);
    lfsr->lfsr_h = (lfsr->lfsr_h >> 1) | (bit_l << 63);

    if(return_flag == 1) { 
        return shifted_bit;
    } else if(return_flag == 2) {
        return bit_l; 
    } else {
        exit(EXIT_FAILURE);
    } 
}



/***********    END OF INITIALIZATION    ***********/ 



/***********    START OF FILE MAPPER    ***********/ 

int list_directory_contents(char *sDir) {
    WIN32_FIND_DATA fdFile;
    HANDLE hFind = NULL;
    char sPath[2048];

    FILE *fp_writer = fopen("map.txt", "a");
    
    if(fp_writer == NULL) {
        perror("Couldn't open writer\n");
        exit(EXIT_FAILURE);
    }

    sprintf(sPath, "%s\\*.*", sDir);

    if((hFind = FindFirstFile(sPath, &fdFile)) == INVALID_HANDLE_VALUE) {
        printf("Path not found: [%s]\n", sDir);
        return FALSE;
    }

    do {
        if(strcmp(fdFile.cFileName, ".") != 0 && strcmp(fdFile.cFileName, "..") != 0) {
            sprintf(sPath, "%s\\%s", sDir, fdFile.cFileName);

            if(fdFile.dwFileAttributes &FILE_ATTRIBUTE_DIRECTORY) {
                list_directory_contents(sPath); 
            } else {
                fprintf(fp_writer, "%s\n", sPath);
                fflush(stdout);
            }
        }
    } while(FindNextFile(hFind, &fdFile)); 

    FindClose(hFind); 
    fclose(fp_writer);

    return TRUE;
}


/***********    END OF THE FILE MAPPER    ***********/ 


/***********    START OF ENCRYPTION    ***********/ 

const char *get_filename_ext(int gui_flag, lfsr128x3_t *lfsr) {
    char sPath[2048] = "\0";
    FILE *fp_reader;
    FILE *fp_enc_writer;
    FILE *fp_enc_reader; 
    
    fp_reader = fopen("map.txt", "r"); 
    fp_enc_writer = fopen("map_enc.txt", "a");
    
    char extension[4];
    const char enc[4] = "enc";
    char new_filename[2048];
    const char append_ext[5] = ".enc";
    char temp_arr[2048];
    int ext_counter = 0;
    int len;
    int position;

    if(gui_flag == 0) {
        fp_enc_reader = fopen("map_enc.txt", "r");

        if((fp_enc_reader) == NULL) {
            perror("Unable to read file. File may not exist.\n");
            exit(EXIT_FAILURE);
        }

        while(fgets(sPath, sizeof(sPath), fp_enc_reader)) {
            sPath[strlen(sPath) - 1] = '\0';

            for(int i = 0; i <= strlen(sPath); i++) {
                new_filename[i] = sPath[i]; 
            }

            len = strlen(sPath);
            position = len - 4;
            new_filename[position] = '\0';

            for (int i = 0; i <= 3; i++) {
                extension[i] = sPath[len - 3 + i];
            }

            if(strncmp(strlwr(extension), enc, 3) == 0) {
                encrypt_decrypt_init(lfsr, sPath);
                rename(sPath, new_filename);
            } else {
                continue; 
            }
        }
    } else if(gui_flag == 1) {
        if((fp_reader) == NULL) {
            perror("Unable to read file\n");
            exit(EXIT_FAILURE);
        }

        while(fgets(sPath, sizeof(sPath), fp_reader)) {
            sPath[strlen(sPath) - 1] = '\0';

            for(int i = 0; i <= strlen(sPath); i++) {
                new_filename[i] = sPath[i]; 
                temp_arr[i] = sPath[i];
            }

            strcat(temp_arr, ".enc");
            fprintf(fp_enc_writer, "%s\n", temp_arr);
            fflush(stdout);

            len = strlen(sPath);

            for(int i = strlen(new_filename); i <= ((strlen(new_filename) - 2) + ((strlen(append_ext) - 2))); i++) {
                new_filename[i] = append_ext[ext_counter];
                ext_counter++;
            }

            for (int i = 0; i <= 3; i++) {
                extension[i] = sPath[len - 3 + i];
            }

            if(strncmp(strlwr(extension), enc, 3) != 0) {
                encrypt_decrypt_init(lfsr, sPath);
                rename(sPath, new_filename);
                ext_counter = 0;
            } else {
                continue; 
            }
        }
    } else {
        printf("Extension comparison error occurred.\nExiting program.\n");
        exit(EXIT_FAILURE);
    }

    SetFileAttributesA("map_enc.txt", FILE_ATTRIBUTE_HIDDEN);
    fclose(fp_reader); 
    remove("map.txt");
    fclose(fp_enc_writer);

    if(gui_flag == 0) {
        fclose(fp_enc_reader);

        if(remove("map_enc.txt") == 0) {
        } 
    }
}

void encrypt_decrypt_init(lfsr128x3_t *lfsr, char *sPath) {
    char *input_fn = sPath;

    FILE *fp_input = fopen(input_fn, "rb+");
    
    if(!fp_input) {
        perror("Couldn't open input");
        exit(EXIT_FAILURE);
    }

    uint8_t buffer[BUFFER_SIZE];
    size_t size;

    fseek(fp_input, 0, SEEK_SET);

    while((size = fread(buffer, 1, BUFFER_SIZE, fp_input)) == BUFFER_SIZE) {
        buffer_encrypter(buffer, lfsr, size);
        fseek(fp_input, -BUFFER_SIZE, SEEK_CUR);
        fwrite(buffer, 1, size, fp_input);
        fseek(fp_input, 0L, SEEK_CUR);
    }

    if(size > 0) {
        buffer_encrypter(buffer, lfsr, size);
        fseek(fp_input, -size, SEEK_CUR);
        fwrite(buffer, 1, size, fp_input);
    }

    fclose(fp_input);
}

void buffer_encrypter(uint8_t *buffer, lfsr128x3_t *lfsr, int size) {
    for(int i=0; i < size; i++) {   
        buffer[i] = buffer[i] ^ (uint8_t)return_for_encryption(lfsr, 8);
    }
}

uint64_t return_for_encryption(lfsr128x3_t *lfsr, uint8_t size) {
    uint64_t r = 0;
    int i;

    r = shift_decimator(lfsr);

    for (i = 0; i < size - 1; i++) { 

        r = r << 1;

        r = r | shift_decimator(lfsr);
    }

    return r;
}

uint64_t shift_decimator(lfsr128x3_t *lfsr) {
    uint64_t r0, r1, r2;

    r0 = lfsr_shift_and_carry_bit(&lfsr->lfsr[0], 1);
    r1 = lfsr_shift_and_carry_bit(&lfsr->lfsr[1], 1);
    r2 = lfsr_shift_and_carry_bit(&lfsr->lfsr[2], 2);

    if (r2 == 1) {
        r0 = lfsr_shift_and_carry_bit(&lfsr->lfsr[0], 1);
        r1 = lfsr_shift_and_carry_bit(&lfsr->lfsr[1], 1);
        r1 = lfsr_shift_and_carry_bit(&lfsr->lfsr[1], 1);
    }

    return r0 ^ r1;
}



/***********    END OF ENCRYPTION    ***********/



int main(int argc, char *argv[], int gui_flag) {
    lfsr128x3_t lfsr;

    char directory_path[] = "SecureFolder";
    unsigned char *password = NULL;
    /*
        These variables are only used for creating a timer that will be used 
        to determine the time it took, in seconds, to encrypt or decrypt the 
        SecureFolder. 
    */
    // time_t start, stop;
    // start = time(NULL);

    if(argc != 3) {
        printf("Unexpected number of arguments given.\nExiting program.\n");
        return EXIT_FAILURE; 
    }

    password = argv[1];

    gui_flag = strtol(argv[2], NULL, 10); 


    if(password == NULL) {
        fprintf(stderr, "Password required.\n\n");
        exit(EXIT_FAILURE);
    }

    lfsr_array_init(&lfsr, password);

    if(gui_flag == 1) {
        list_directory_contents(directory_path);
    } 

    get_filename_ext(gui_flag, &lfsr);

    // printf("Program operations complete\n");

    /* 
        The below three lines are only used to test if the program ran successfully
        if this program is launched via the GUI, in which no command prompt messages
        or printf() statements will be visible. The test is that a blank text file is 
        created that is easy to see to confirm that the program did run successfully.  
    */
    // FILE *fp;
    // fp = fopen("done.txt", "w");
    // fclose(fp);

    /*
        These lines are used for testing the time it takes to encrypt or decrypt the 
        SecureFolder. Time is measured in seconds. 
    */
    // stop = time(NULL);  
    // printf("The number of seconds for loop to run was %ld\n", stop - start);
    // Sleep(5000000);

    return EXIT_SUCCESS;
}
