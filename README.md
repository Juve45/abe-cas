# abe-cas
Attribute Based Encryption for Compartmented  Access Structure

We provide implementation for an Attribute Based Encryption with Compartmented Access Structure
The implementation is written fully in C



 

# Encryption

The encryption algorithm encrypts an element from `mpz_t`.
It returns a tuple (for convenience a `struct Ciphertext_SSBM_ABE` was created), that contains the elements...

Examples:
```C
public_param_SSBM_ABE pp;
secret_param_SSBM_ABE msk;

setup(pp, msk, 4, 0);

mpz_t msg;
mpz_init_set_si(msg, 1234567891);

int arr [] = {0, 1, 2};

ciphertext_SSBM_ABE ct;

encrypt(ct, pp, msg, arr, 3);
```



# KeyGeneration
This algorithm recieves a compartmented acces structure, and returns the decryption keys corresponding to it.

The compartmented access structure should be given as an `int **`. Each `int*` represents a compartment.

Example:

```C
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

```


# Decryption
The encryption algorithm encrypts an element from `mpz_t`.

Example: 
```C
mpz_t message;

int ret = decrypt(message, cas, dec, pp, ct);

if(ret == 0)
	element_printf("The descrypted message is: %Zd\n", message);
else 
	element_printf("The message could not be decrypted\n");
```

