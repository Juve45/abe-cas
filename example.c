#include "ssbm.h"

int main(int argc, char const *argv[]) {
	
	public_param_SSBM_ABE pp;
	secret_param_SSBM_ABE msk;
	ciphertext_SSBM_ABE ct;
	setup(pp, msk, 4, 0);

	mpz_t msg;
	mpz_init_set_si(msg, 1234567891);



	int arr [] = {0, 1, 2};

	encrypt(ct, pp, msg, arr, 3);
	compartmented_access_str cas;

	// initializing the compartmented access structure
	int compartments[2][2] = {
		{0, 3},
		{1, 2}
	};
	int sz[2] = {2, 2};
	int thresh[2] = {1, 1}; 

	cas->n = 4;
	cas->t = 3;
	cas->comp_number = 2;
	cas->compartments 		= (int **) calloc(2, sizeof(int*));
	cas->compartments[0] 		= compartments[0];
	cas->compartments[1] 		= compartments[1];
	cas->comp_size 				= sz;
	cas->comp_threshold 	= thresh;
	// end of CAS initializing

	decryption_key_SSBM_ABE dec;
	key_generation(dec, pp, msk, cas);

	printf("The decryption key was generated!\n");

	printf("========\n\n");

	mpz_t message;

	int ret = decrypt(message, cas, dec, pp, ct);
	
	// printf("%d\n", ret);
	// element_printf("%B", message);
	if(ret == 0)
		element_printf("The descrypted message is: %Zd\n", message);
	else 
		element_printf("The message could not be decrypted\n");

	return 0;
}

//TODO clean up after use!!!! 