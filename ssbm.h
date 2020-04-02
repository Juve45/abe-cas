#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>


typedef struct Public_param_SSBM_ABE {
	pairing_t pairing;
	element_t g, Y;
	element_t *T;
	int n;
} public_param_SSBM_ABE[1];

typedef struct Secret_param_SSBM_ABE {
	element_t y;
	element_t *t;
	int n;
} secret_param_SSBM_ABE[1];

/**
 * @brief [brief description]
 * @details [long description]
 * 
 * E has attr_count elements, the keys corresponding to 
 * the [attributes] vector 
 */
typedef struct Ciphertext_SSBM_ABE {
	element_t M, S;
	element_t * E;
	mpz_t extra;
	int * attributes, attr_count;
} ciphertext_SSBM_ABE[1];

struct key {
	element_t value;
	int undefined;
};

typedef struct Compartmented_access_str {
	int n, t, comp_number;
	int * comp_size, * comp_threshold;
	int ** compartments;
} compartmented_access_str[1];

typedef struct Decryption_key_SSBM_ABE {
	int n;
	element_t * a1, * a2;
} decryption_key_SSBM_ABE[1];


void setup(public_param_SSBM_ABE public_key, secret_param_SSBM_ABE master_key, int n,  int lambda);

void encrypt(ciphertext_SSBM_ABE ciphertext, public_param_SSBM_ABE public_key, mpz_t message, int * attributes, int attr_count);

// all elements should be initialised prior to the function call->
void element_polynomial_eval(element_t ans, element_t * a, int degree, element_t x);

void element_polynomial_interpolation_in0(element_t result, element_t * values, element_t * points, int degree, public_param_SSBM_ABE public_key);

/**
 * @brief generates the key for decryption
 * @details [long description]
 * 
 * @param decryption_key [description]
 * @param public_key [description]
 * @param secret_key [description]
 * @param cas [description]
 * @return true if the decryption was successfull, false otherwise
 */
int key_generation(decryption_key_SSBM_ABE decryption_key, public_param_SSBM_ABE public_key, secret_param_SSBM_ABE secret_key, compartmented_access_str cas);

int decrypt(mpz_t message, compartmented_access_str cas, decryption_key_SSBM_ABE decryption_key, public_param_SSBM_ABE public_key, ciphertext_SSBM_ABE ciphertext);