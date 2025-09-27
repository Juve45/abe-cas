// EDUCATIONAL NOTE: Example implementation of ABE (Attribute-Based Encryption)
// This demonstrates the basic usage of the SSBM ABE scheme
// SECURITY WARNING: This is for educational purposes only - not production ready

#include "ssbm.h"

int main(int argc, char const *argv[]) {

	// SECURITY: Initialize all cryptographic structures
	public_param_SSBM_ABE pp;
	secret_param_SSBM_ABE msk;
	ciphertext_SSBM_ABE ct;

	// EDUCATIONAL NOTE: The setup function generates public/private key pairs
	// Parameter 4 = number of attributes, 0 = security parameter (should be larger in practice)
	setup(pp, msk, 4, 0);

	mpz_t msg;
	mpz_init_set_si(msg, 1234567891);

	// EDUCATIONAL NOTE: Define which attributes are used for encryption
	// These are the attribute indices (0, 1, 2) that will be required for decryption
	int arr [] = {0, 1, 2};

	// EDUCATIONAL NOTE: Encrypt the message under the specified attributes
	encrypt(ct, pp, msg, arr, 3);
	compartmented_access_str cas;

	// EDUCATIONAL NOTE: Compartmented Access Structure (CAS) setup
	// This defines how attributes are grouped and what thresholds are needed
	int compartments[2][2] = {
		{0, 3}, // Compartment 1: attributes 0 and 3
		{1, 2}  // Compartment 2: attributes 1 and 2
	};
	int sz[2] = {2, 2};       // Each compartment has 2 attributes
	int thresh[2] = {1, 1};   // Need 1 attribute from each compartment

	cas->n = 4;               // Total number of attributes
	cas->t = 3;               // Global threshold (need 3 attributes total)
	cas->comp_number = 2;     // Number of compartments

	// SECURITY FIX: Check memory allocation
	cas->compartments = (int **) calloc(2, sizeof(int*));
	if (!cas->compartments) {
		printf("Memory allocation failed for compartments\n");
		return 1;
	}
	cas->compartments[0] = compartments[0];
	cas->compartments[1] = compartments[1];
	cas->comp_size = sz;
	cas->comp_threshold = thresh;
	// end of CAS initializing

	decryption_key_SSBM_ABE dec;
	key_generation(dec, pp, msk, cas);

	printf("The decryption key was generated!\n");

	printf("========\n\n");

	// EDUCATIONAL NOTE: Attempt to decrypt the ciphertext
	mpz_t message;

	int ret = decrypt(message, cas, dec, pp, ct);

	if(ret == 0) {
		element_printf("The decrypted message is: %Zd\n", message);
	} else {
		element_printf("The message could not be decrypted\n");
	}

	// SECURITY FIX: Proper memory cleanup to prevent memory leaks
	// Clean up allocated memory
	if (cas->compartments) {
		free(cas->compartments);
	}

	// Clean up mpz variables
	mpz_clear(msg);
	mpz_clear(message);

	// Note: In a full implementation, all element_t structures should also be cleared
	// This requires calling element_clear() for each initialized element

	return 0;
} 