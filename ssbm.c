#include "ssbm.h"

void setup(public_param_SSBM_ABE public_key, secret_param_SSBM_ABE master_key, int n,  int lambda) {

	// SECURITY: Validate input parameters
	if (!public_key || !master_key || n <= 0 || n > 10000) {
		return; // Invalid parameters - prevent buffer overflows
	}

	master_key->n = public_key->n = n;

	// SECURITY WARNING: Using predetermined pairing parameters for compatibility
	// In production environments, use cryptographically secure parameter generation
	// These parameters should be verified and come from trusted sources
	if (pairing_init_set_str(public_key->pairing, "type a\nq 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1\n") != 0) {
		// Pairing initialization failed
		return;
	}

	// set up private parameters
	// SECURITY FIX: Check for allocation failure
	master_key->t = (element_t *) calloc(n, sizeof(element_t));
	if (!master_key->t) {
		return; // Memory allocation failed
	}

	element_init_Zr(master_key->y, public_key->pairing);
	element_random(master_key->y);

	for(int i = 0; i < n; i++) {
		element_init_Zr(master_key->t[i], public_key->pairing);
		element_random(master_key->t[i]);
	}

	// set up public parameters
	element_init_G1(public_key->g, public_key->pairing);
	element_random(public_key->g);
	element_init_GT(public_key->Y, public_key->pairing);	
	pairing_apply(public_key->Y, public_key->g, public_key->g,public_key->pairing);
	element_pow_zn(public_key->Y, public_key->Y, master_key->y);

	// SECURITY FIX: Check for allocation failure
	public_key->T = (element_t *) calloc(n, sizeof(element_t));
	if (!public_key->T) {
		// Clean up previously allocated memory
		free(master_key->t);
		return; // Memory allocation failed
	}
	for(int i = 0; i < n; i++) {
		element_init_G1(public_key->T[i], public_key->pairing);	
		element_pow_zn(public_key->T[i], public_key->g, master_key->t[i]);
	}
}

void encrypt(ciphertext_SSBM_ABE ciphertext, public_param_SSBM_ABE public_key, mpz_t message, int * attributes, int attr_count) {

	// SECURITY: Validate input parameters
	if (!ciphertext || !public_key || !message || !attributes || attr_count <= 0 || attr_count > public_key->n) {
		return; // Invalid parameters
	}

	mpz_t msg_gt;
	element_t message_GT, Ys;
	element_init_GT(message_GT, public_key->pairing);
	element_init_GT(Ys, public_key->pairing);
	element_init_GT(ciphertext->M, public_key->pairing);
	ciphertext->attr_count = attr_count;

	// SECURITY FIX: Use cryptographically secure random generation
	element_random(message_GT);
	// SECURITY: Remove debug output to prevent information leakage in production
	#ifdef DEBUG_CRYPTO
	element_printf("Message in GT: %B\n", message_GT);
	#endif

	mpz_init(ciphertext->extra);
	mpz_init(msg_gt);
	element_to_mpz(msg_gt, message_GT);
	mpz_sub(ciphertext->extra, message , msg_gt);

	// gmp_printf("Message in mpz: %Zd\n", message);

	element_t s;
	element_init_Zr(s, public_key->pairing);

	element_pow_zn(Ys, public_key->Y, s);
	element_mul(ciphertext->M, message_GT, Ys); // generate M*g^(ys)

	element_init_G1(ciphertext->S, public_key->pairing);
	element_random(s);
	element_pow_zn(ciphertext->S, public_key->g,s); // generate g^s

	// SECURITY FIX: Check memory allocation failures
	ciphertext->E = (element_t *) calloc(attr_count, sizeof(element_t));
	if (!ciphertext->E) {
		return; // Memory allocation failed
	}

	ciphertext->attributes = (int *) calloc(attr_count, sizeof(int));
	if (!ciphertext->attributes) {
		free(ciphertext->E); // Clean up previous allocation
		return; // Memory allocation failed
	}

	for(int i = 0; i < attr_count; i++) { // generate A and T_i
		int which = attributes[i];
		// SECURITY FIX: Validate attribute index to prevent buffer overflow
		if (which < 0 || which >= public_key->n) {
			// Clean up and return on invalid attribute
			free(ciphertext->E);
			free(ciphertext->attributes);
			return;
		}
		ciphertext->attributes[i] = attributes[i];
		element_init_G1(ciphertext->E[i], public_key->pairing);
		element_pow_zn(ciphertext->E[i], public_key->T[which], s);
	}
}

// all elements should be initialised prior to the function call->
void element_polynomial_eval(element_t ans, element_t * a, int degree, element_t x) {
	element_t tmp;
	element_t x_pow;
	element_init_same_as(x_pow, ans);
	element_set1(x_pow);
	element_set0(ans);

	// the polynomial has degree+1 indices
	for(int i = 0; i <= degree; i++) { 
		// printf("poly %d\n", i);
		element_init_same_as(tmp, ans);
		element_set(tmp, a[i]);
		element_mul(tmp, tmp, x_pow);
		element_add(ans, ans, tmp);
		element_mul(x_pow, x_pow, x);
	}
}

void element_polynomial_interpolation_in0(element_t result, element_t * values, element_t * points, int degree, public_param_SSBM_ABE public_key) {

	element_set1(result);
	// printf("enter %d\n", degree);

	for(int i = 0; i < degree; i++) {
		// printf("interp %d\n", i);
		element_t exponent;
		element_init_Zr(exponent, public_key->pairing);

		for(int j = 0; j < degree; j++) {
			if(i == j) continue;
			element_t tmp;
			element_init_Zr(tmp, public_key->pairing);
			// exponent *= points[i] / (points[i] - points[j])
			element_set(tmp, points[i]);
			// element_printf("i j %d %d %B\n", i, j, points[j - 1]);
			element_sub(tmp, tmp, points[j]);
			element_div(tmp, points[i], tmp);
			element_mul(exponent, exponent, tmp);
		}

		element_t tmp_gt;
		element_init_GT(tmp_gt, public_key->pairing);
		pairing_apply(tmp_gt, public_key->g, public_key->g, public_key->pairing);
		element_pow_zn(tmp_gt, tmp_gt, exponent);
		element_mul(result, result, tmp_gt);
	}
	// printf("exit\n");
}


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
int key_generation(decryption_key_SSBM_ABE decryption_key, public_param_SSBM_ABE public_key, secret_param_SSBM_ABE secret_key, compartmented_access_str cas) {
	// SECURITY: Validate input parameters
	if (!decryption_key || !public_key || !secret_key || !cas) {
		return 0; // NULL pointer protection
	}

	if(public_key->n != cas->n)
		return 0;

	// SECURITY: Validate compartment structure to prevent buffer overflows
	if (cas->comp_number <= 0 || cas->comp_number > 1000 || cas->t <= 0 || cas->t > cas->n) {
		return 0; // Invalid compartment configuration
	}

	decryption_key->n = public_key->n;

	int share_count = cas->comp_number + 1;
	element_t * share = (element_t *) calloc(share_count, sizeof(element_t ));
	decryption_key->a1 = (element_t *) calloc(public_key->n, sizeof(element_t ));
	decryption_key->a2 = (element_t *) calloc(public_key->n, sizeof(element_t ));

	element_t sum;
	element_init_Zr(sum, public_key->pairing);
	element_set(sum, secret_key->y);

	// printf(" inside keygen %d\n", decryption_key->n);

	for(int i = 0; i < cas->comp_number; i++) {

		element_init_Zr(share[i], public_key->pairing);
		element_random(share[i]);
		element_sub(sum, sum, share[i]);

		// SECURITY FIX: Validate threshold before creating VLA (Variable Length Array)
		if (cas->comp_threshold[i] <= 0 || cas->comp_threshold[i] > 1000) {
			return 0; // Prevent stack overflow from large VLA
		}

		// generez polinomul de grad k - 1!!!!
		element_t a[cas->comp_threshold[i]];
		element_init_Zr(a[0], public_key->pairing);
		element_set(a[0], share[i]);

		
		for(int j = 1; j < cas->comp_threshold[i]; j++) {
			element_init_Zr(a[j], public_key->pairing);
			element_random(a[j]);
		}


		for(int j = 0; j < cas->comp_size[i]; j++) {
			// SECURITY FIX: Validate compartment indices before array access
			if (cas->compartments[i][j] < 0 || cas->compartments[i][j] >= public_key->n) {
				return 0; // Invalid compartment index
			}

			//polinom de grad comp)threshold[i];
			element_t tmp, x;
			element_init_Zr(tmp, public_key->pairing);
			element_init_Zr(x, public_key->pairing);
			element_set_si(x, j + 1); // WARNING! Change in indices
			// printf("%d %d\n", i, j);
			element_polynomial_eval(tmp, a, cas->comp_threshold[i] - 1, x);
			element_init_G1(decryption_key->a1[cas->compartments[i][j]], public_key->pairing);
			element_div(tmp, tmp, secret_key->t[cas->compartments[i][j]]);
			element_pow_zn(decryption_key->a1[cas->compartments[i][j]], public_key->g, tmp);
		}
	}

	//setting the last threshold gate
	element_init_Zr(share[cas->comp_number], public_key->pairing);
	element_set(share[cas->comp_number], sum);

	// SECURITY FIX: Additional validation for threshold parameter
	if (cas->t <= 0 || cas->t > 1000) {
		// Clean up allocated memory before returning
		for (int k = 0; k < share_count; k++) {
			element_clear(share[k]);
		}
		free(share);
		free(decryption_key->a1);
		free(decryption_key->a2);
		return 0; // Prevent stack overflow from large VLA
	}

	element_t b[cas->t];
	//generez polynom de grad t - 1
	for(int j = 0; j < cas->t; j++)
			element_init_Zr(b[j], public_key->pairing);
		
	for(int j = 1; j < cas->t; j++) {
		element_init_Zr(b[j], public_key->pairing);
		element_random(b[j]);
	}

	for(int j = 0; j < cas->n; j++) {
		//polinom de grad comp)threshold[i];
		element_t tmp, x;
		element_init_Zr(tmp, public_key->pairing);
		element_init_Zr(x, public_key->pairing);
		element_set_si(x, j + 1); // WARNING! Change in indices
		element_polynomial_eval(tmp, b, cas->t - 1, x);

		element_init_G1(decryption_key->a2[j], public_key->pairing);
		element_div(tmp, tmp, secret_key->t[j]);
		element_pow_zn(decryption_key->a2[j], public_key->g, tmp);
	}

	for (int i = 0; i < share_count; i++) {
		element_clear(share[i]);
	};
	free(share);
	return 1;
}

int decrypt(mpz_t message, compartmented_access_str cas, decryption_key_SSBM_ABE decryption_key, public_param_SSBM_ABE public_key, ciphertext_SSBM_ABE ciphertext) {

	// SECURITY: Validate input parameters to prevent null pointer dereferences
	if (!cas || !decryption_key || !public_key || !ciphertext || !message) {
		return 1; // Invalid input parameters
	}

	// invAttr[i] keeps the position of attribute i in `ciphertext->attributes`
	if(ciphertext->attr_count < cas->t) return 1;

	// SECURITY FIX: Bounds checking - ensure public_key->n is reasonable to prevent stack overflow
	if (public_key->n <= 0 || public_key->n > 10000) {
		return 1; // Invalid attribute count - prevent buffer overflow
	}

	int invAttr[public_key->n];
	// SECURITY FIX: Proper initialization - memset with -1 might not work as expected for int arrays
	// Use a loop to ensure proper initialization
	for (int i = 0; i < public_key->n; i++) {
		invAttr[i] = -1;
	}

	// SECURITY FIX: Bounds checking for array access
	for(int i = 0; i < ciphertext->attr_count; i++) {
		// Validate attribute index before using as array index
		if (ciphertext->attributes[i] >= 0 && ciphertext->attributes[i] < public_key->n) {
			invAttr[ciphertext->attributes[i]] = i;
		} else {
			// Invalid attribute index - could cause buffer overflow
			return 1;
		}
	}

	element_t share[cas->comp_number + 1];
	
	for(int i = 0; i < cas->comp_number; i++) {

		element_init_GT(share[i], public_key->pairing);
		// element_t keys[cas->comp_threshold[i]];
		int attr_found = 0, j = 0;
		element_t values[cas->comp_threshold[i]], points[cas->comp_threshold[i]];

		while(attr_found < cas->comp_threshold[i] && j < cas->comp_size[i]) {
			// SECURITY FIX: Additional bounds checking for compartment access
			if (cas->compartments[i][j] >= 0 && cas->compartments[i][j] < public_key->n &&
			    invAttr[cas->compartments[i][j]] != -1) {
				// SECURITY: Remove debug output to prevent information leakage
				#ifdef DEBUG_CRYPTO
				printf("%d %d\n", invAttr[cas->compartments[i][j]], cas->compartments[i][j]);
				#endif
				element_init_GT(values[attr_found], public_key->pairing);
				element_init_Zr(points[attr_found], public_key->pairing);
				element_set_si(points[attr_found], cas->compartments[i][j] + 1);
				// Additional bounds check for ciphertext->E array access
				int attr_index = invAttr[cas->compartments[i][j]];
				if (attr_index >= 0 && attr_index < ciphertext->attr_count) {
					pairing_apply(values[attr_found], ciphertext->E[attr_index],
					              decryption_key->a1[cas->compartments[i][j]], public_key->pairing);
					attr_found++;
				}
			}
			j++;
		}
		if(attr_found < cas->comp_threshold[i])
			return 1;

		element_polynomial_interpolation_in0(share[i], values, points, cas->comp_threshold[i], public_key);
	}

	
	element_init_GT(share[cas->comp_number], public_key->pairing);
	// element_t keys[cas->t];
	int attr_found = 0, j = 0;
	element_t values[cas->t], points[cas->t];

	// SECURITY FIX: Bounds checking for threshold gate computation
	for(int i = 0; i < cas->t && i < ciphertext->attr_count; i++) {
		element_init_GT(values[i], public_key->pairing);
		element_init_Zr(points[i], public_key->pairing);
		element_set_si(points[i], j + 1);
		// Validate array bounds before access
		if (ciphertext->attributes[i] >= 0 && ciphertext->attributes[i] < public_key->n) {
			pairing_apply(values[i], ciphertext->E[i], decryption_key->a2[ciphertext->attributes[i]], public_key->pairing);
		} else {
			return 1; // Invalid attribute index
		}
	}

	element_polynomial_interpolation_in0(share[cas->comp_number], values, points, cas->t, public_key);

	element_t Ys, msg_gt;
	element_init_GT(Ys, public_key->pairing);
	element_set1(Ys);
	for(int i = 0; i <= cas->comp_number; i++) 
		element_mul(Ys, Ys, share[i]); // we actually do not need the share array-> Just compute this in for loop

	element_init_GT(msg_gt, public_key->pairing);
	element_mul(msg_gt, ciphertext->M, Ys);
	mpz_init(message);
	element_to_mpz(message, msg_gt);
	// printf("ajung pe la final\n");
	mpz_add(message, message, ciphertext->extra);
	return 0;
}

// SECURITY: Memory cleanup functions to prevent sensitive data leakage

void cleanup_public_params(public_param_SSBM_ABE public_key) {
	if (!public_key) return;

	if (public_key->T && public_key->n > 0) {
		for (int i = 0; i < public_key->n; i++) {
			element_clear(public_key->T[i]);
		}
		free(public_key->T);
		public_key->T = NULL;
	}

	element_clear(public_key->g);
	element_clear(public_key->Y);
	pairing_clear(public_key->pairing);
	public_key->n = 0;
}

void cleanup_secret_params(secret_param_SSBM_ABE secret_key) {
	if (!secret_key) return;

	if (secret_key->t && secret_key->n > 0) {
		for (int i = 0; i < secret_key->n; i++) {
			element_clear(secret_key->t[i]);
		}
		free(secret_key->t);
		secret_key->t = NULL;
	}

	element_clear(secret_key->y);
	secret_key->n = 0;
}

void cleanup_ciphertext(ciphertext_SSBM_ABE ciphertext) {
	if (!ciphertext) return;

	if (ciphertext->E && ciphertext->attr_count > 0) {
		for (int i = 0; i < ciphertext->attr_count; i++) {
			element_clear(ciphertext->E[i]);
		}
		free(ciphertext->E);
		ciphertext->E = NULL;
	}

	if (ciphertext->attributes) {
		free(ciphertext->attributes);
		ciphertext->attributes = NULL;
	}

	element_clear(ciphertext->M);
	element_clear(ciphertext->S);
	mpz_clear(ciphertext->extra);
	ciphertext->attr_count = 0;
}

void cleanup_decryption_key(decryption_key_SSBM_ABE decryption_key) {
	if (!decryption_key) return;

	if (decryption_key->a1 && decryption_key->n > 0) {
		for (int i = 0; i < decryption_key->n; i++) {
			element_clear(decryption_key->a1[i]);
		}
		free(decryption_key->a1);
		decryption_key->a1 = NULL;
	}

	if (decryption_key->a2 && decryption_key->n > 0) {
		for (int i = 0; i < decryption_key->n; i++) {
			element_clear(decryption_key->a2[i]);
		}
		free(decryption_key->a2);
		decryption_key->a2 = NULL;
	}

	decryption_key->n = 0;
}

void cleanup_cas(compartmented_access_str cas) {
	if (!cas) return;

	if (cas->compartments && cas->comp_number > 0) {
		for (int i = 0; i < cas->comp_number; i++) {
			if (cas->compartments[i]) {
				free(cas->compartments[i]);
			}
		}
		free(cas->compartments);
		cas->compartments = NULL;
	}

	if (cas->comp_size) {
		free(cas->comp_size);
		cas->comp_size = NULL;
	}

	if (cas->comp_threshold) {
		free(cas->comp_threshold);
		cas->comp_threshold = NULL;
	}

	cas->n = 0;
	cas->t = 0;
	cas->comp_number = 0;
}
