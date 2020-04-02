#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>


typedef struct _public_param_SSBM_ABE {
	pairing_t pairing;
	element_t g, Y;
	element_t *T;
	int n;
} public_param_SSBM_ABE[1];


/**
 * @brief struct describing Master Secret Key
 * @details 
 * 
 */
typedef struct _secret_param_SSBM_ABE {
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
typedef struct _ciphertext_SSBM_ABE {
	element_t M, S;
	element_t * E;
	mpz_t extra;
	int * attributes, attr_count;
} ciphertext_SSBM_ABE[1];

struct key {
	element_t value;
	int undefined;
};

typedef struct _compartmented_access_str {
	int n, t, comp_number;
	int * comp_size, * comp_threshold;
	int ** compartments;
} compartmented_access_str[1];


typedef struct _decryption_key_SSBM_ABE {
	int n;
	element_t * a1, * a2;
} decryption_key_SSBM_ABE[1];

/**
 * @brief setup function, generating the publib/secret parameters
 * @details This function generates the public and the secret keys for our encryption.
 * 
 * @param public_key The public key that will be returned
 * @param master_key The master secret key that will be returned
 * @param n is the total number of attributes in the system
 * @param lambda security parameter TODO
 */
void setup(public_param_SSBM_ABE public_key, secret_param_SSBM_ABE master_key, int n,  int lambda);

/**
 * @brief The encryption function
 * @details This function takes as arguments the public parameters, a set of attributes and a 
 * message from `mpz_t` and returns the encryption of it under the set of attributes.
 * 
 * @param ciphertext The ciphertext that is to be returned
 * @param public_key the public key
 * @param message the message to be encrypted
 * @param attributes a pointer to an array containg the attribute set which is used to encrypt the message
 * @param attr_count size of the vector `attributes`
 */
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


/**
 * @brief the decryption algorithm
 * @details This algorithm decrypts a ciphertext
 * 
 * @param message [description]
 * @param cas [description]
 * @param decryption_key [description]
 * @param public_key [description]
 * @param ciphertext [description]
 * @return [description]
 */
int decrypt(mpz_t message, compartmented_access_str cas, decryption_key_SSBM_ABE decryption_key, public_param_SSBM_ABE public_key, ciphertext_SSBM_ABE ciphertext);