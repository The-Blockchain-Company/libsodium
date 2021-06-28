#include <string.h>

#include "crypto_hash_sha512.h"
#include "crypto_vrf_twohashdh.h"
#include "crypto_core_ed25519.h"
#include "private/ed25519_ref10.h"
#include "utils.h"
#include "vrf_twohashdh.h"

/* Construct a proof for a message alpha per draft spec section 5.1.
 * Takes in a secret scalar x, a public point Y, and a secret string
 * truncated_hashed_sk that is used in nonce generation.
 * These are computed from the secret key using the expand_sk function.
 * Constant time in everything except alphalen (the length of the message)
 */
static void
vrf_prove(unsigned char pi[crypto_vrf_twohashdh_PROOFBYTES], const ge25519_p3 *Y_point,
          const unsigned char x_scalar[32],
          const unsigned char *alpha, unsigned long long alphalen)
{
    unsigned char h_string[32], random_proof[32], challenge_scalar[32], response_scalar[32], proof_randomness[64];
    ge25519_p3    H_point, U_point, Announcement_one, Announcement_two;

    _vrf_twohashdh_hash_to_curve_elligator2_25519(h_string, alpha, alphalen);
    ge25519_frombytes(&H_point, h_string);

    ge25519_scalarmult(&U_point, x_scalar, &H_point); /* U_point = x*H */

    // Now we perform a proof of DLOG equality
    /* Announcement */
    crypto_core_ed25519_scalar_random(&random_proof);
    ge25519_scalarmult_base(&Announcement_one, &random_proof);
    ge25519_scalarmult(&Announcement_two, &random_proof, &H_point);

    unsigned char u_string[32], a_one[32], a_two[32];
    /* challenge = hash_points(Y_point, H_point, U_point, Announcement_one, Announcement_two) */
    printf("H_point (prover):");
    for (int i = 0; i<32; i++) {
        printf("%c", h_string[i]);
    }
    printf("\n");
    ge25519_tobytes(u_string, &U_point);
    printf("U_point (prover):");
    for (int i = 0; i<32; i++) {
        printf("%c", u_string[i]);
    }
    printf("\n");
    ge25519_tobytes(a_one, &Announcement_one);
    printf("Announcement1 (prover):");
    for (int i = 0; i<32; i++) {
        printf("%c", a_one[i]);
    }
    printf("\n");
    ge25519_tobytes(a_two, &Announcement_two);
    printf("Announcement2 (prover):");
    for (int i = 0; i<32; i++) {
        printf("%c", a_two[i]);
    }
    printf("\n");
    _vrf_twohashdh_hash_points(challenge_scalar, Y_point, &H_point, &U_point, &Announcement_one, &Announcement_two);

    /* Response computed below*/


    /* output pi */
    ge25519_p3_tobytes(pi, &U_point); /* pi[0:32] = U_point */
    memmove(pi+32, challenge_scalar, 32); /* pi[32:64] = challenge (32 bytes) */
    sc25519_muladd(pi+64, challenge_scalar, x_scalar, &random_proof); /* pi[64:96] = s = c*x + k (mod q). RESPONSE HERE */

    sodium_memzero(&random_proof, sizeof random_proof); /* random_proof must remain secret */
    /* todo: erase other non-sensitive intermediate state for good measure */
}

/* Construct a VRF proof given a secret key and a message.
 *
 * The "secret key" is 64 bytes long -- 32 byte secret seed concatenated
 * with 32 byte precomputed public key. Our keygen functions return secret keys
 * of this form.
 *
 * Returns 0 on success, nonzero on failure decoding the public key.
 *
 * Constant time in everything except msglen, unless decoding the public key
 * fails.
 */
int
crypto_vrf_twohashdh_prove(unsigned char proof[crypto_vrf_twohashdh_PROOFBYTES],
                             const unsigned char skpk[crypto_vrf_twohashdh_SECRETKEYBYTES],
                             const unsigned char *msg,
                             unsigned long long msglen)
{
    ge25519_p3    Y_point;
    unsigned char x_scalar[32];

    memmove(x_scalar, skpk, 32);
    if (ge25519_is_canonical(skpk + 32) == 0) {
        printf("not canonical");
        return -1;
    } else if (ge25519_frombytes(&Y_point, skpk + 32) != 0) {
        printf("not from bytes");
        sodium_memzero(x_scalar, 32);
        sodium_memzero(&Y_point, sizeof Y_point); /* for good measure */
        return -1;
    }

    vrf_prove(proof, &Y_point, x_scalar, msg, msglen);
    sodium_memzero(x_scalar, 32);
    sodium_memzero(&Y_point, sizeof Y_point); /* for good measure */
    return 0;
}

