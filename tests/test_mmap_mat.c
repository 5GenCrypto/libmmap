#include <mmap/mmap.h>
#include <mmap/mmap_clt.h>
#ifdef HAVE_GGHLITE
#  include <mmap/mmap_gghlite.h>
#endif
#include <mmap/mmap_dummy.h>
#include <flint/fmpz.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>

#include "utils.h"

/* XXX: Currently, fmpz_modp_matrix_inverse is part of gghlite, whereas it
   should really be within libmmap or something.  This should be fixed! */
#ifdef HAVE_LIBGGHLITE

ulong nzs = 2;
ulong kappa = 2;

const ulong lambdas[] = {8, 16, 24, 32};

static void encode(const mmap_vtable *vtable, mmap_sk sk,
                   mmap_enc_mat_t out, fmpz_mat_t in, int idx, int nrows,
                   int ncols, aes_randstate_t rand)
{
    int *pows;

    pows = calloc(nzs, sizeof(int));
    pows[idx] = 1;

    for (int i = 0; i < nrows; ++i) {
        for (int j = 0; j < ncols; ++j) {
            vtable->enc->encode(out->m[i][j], sk, 1, fmpz_mat_entry(in, i, j),
                                pows);
        }
    }
    free(pows);
}

static void
_fmpz_mat_init_rand(fmpz_mat_t m, long n, aes_randstate_t rand, fmpz_t field)
{
    fmpz_mat_t inverse;

    fmpz_mat_init(m, n, n);
    fmpz_mat_init(inverse, n, n);
    while (true) {
        for (int i = 0; i < n; i++) {
            for(int j = 0; j < n; j++) {
                fmpz_randm_aes(fmpz_mat_entry(m, i, j), rand, field);
            }
        }
        fmpz_modp_matrix_inverse(inverse, m, n, field);
        for (int i = 0; i < n; i++) {
            for(int j = 0; j < n; j++) {
                if (!fmpz_is_zero(fmpz_mat_entry(inverse, i, j)))
                    goto done;
            }
        }
    }
done:
    fmpz_mat_clear(inverse);
}

static inline void
fmpz_mat_mul_mod(fmpz_mat_t a, fmpz_mat_t b, fmpz_mat_t c, fmpz_t p)
{
    fmpz_mat_mul(a, b, c);
    fmpz_mat_scalar_mod_fmpz(a, a, p);
}

static inline void
fmpz_layer_mul_left(fmpz_mat_t zero, fmpz_mat_t one, fmpz_mat_t m, fmpz_t p)
{
    fmpz_mat_mul_mod(zero, m, zero, p);
    fmpz_mat_mul_mod(one, m, one, p);
}

static void
fmpz_layer_mul_right(fmpz_mat_t zero, fmpz_mat_t one, fmpz_mat_t m, fmpz_t p)
{
    fmpz_mat_mul_mod(zero, zero, m, p);
    fmpz_mat_mul_mod(one, one, m, p);
}

static int test(const mmap_vtable *vtable, ulong lambda, bool is_gghlite)
{
    int ok = 1;
    mmap_sk sk = malloc(vtable->sk->size);
    const mmap_pp *pp;

    aes_randstate_t rng;
    aes_randinit(rng);

    fmpz_t *moduli;

    vtable->sk->init(sk, lambda, kappa, nzs, NULL, 0, 0, rng, false);
    moduli = vtable->sk->plaintext_fields(sk);
    pp = vtable->sk->pp(sk);

    if (is_gghlite)
        return 0;               /* TODO: Support gghlite */

    fmpz_mat_t zero_1, one_1, zero_2, one_2, rand, res;
    fmpz_mat_init(zero_1, 1, 2);
    fmpz_mat_init(one_1,  1, 2);
    fmpz_mat_init(zero_2, 2, 2);
    fmpz_mat_init(one_2,  2, 2);
    fmpz_mat_init(res,    1, 2);

    fmpz_set_ui(fmpz_mat_entry(zero_1, 0, 0), 1);
    fmpz_set_ui(fmpz_mat_entry(zero_1, 0, 1), 0);

    fmpz_set_ui(fmpz_mat_entry(one_1, 0, 0), 1);
    fmpz_set_ui(fmpz_mat_entry(one_1, 0, 1), 1);

    fmpz_set_ui(fmpz_mat_entry(zero_2, 0, 0), 1);
    fmpz_set_ui(fmpz_mat_entry(zero_2, 0, 1), 0);
    fmpz_set_ui(fmpz_mat_entry(zero_2, 1, 0), 0);
    fmpz_set_ui(fmpz_mat_entry(zero_2, 1, 1), 0);

    fmpz_set_ui(fmpz_mat_entry(one_2, 0, 0), 1);
    fmpz_set_ui(fmpz_mat_entry(one_2, 0, 1), 0);
    fmpz_set_ui(fmpz_mat_entry(one_2, 1, 0), 0);
    fmpz_set_ui(fmpz_mat_entry(one_2, 1, 1), 1);

    mmap_enc_mat_t zero_enc_1, one_enc_1, zero_enc_2, one_enc_2, result;
    mmap_enc_mat_init(vtable, pp, zero_enc_1, 1, 2);
    mmap_enc_mat_init(vtable, pp, one_enc_1,  1, 2);
    mmap_enc_mat_init(vtable, pp, zero_enc_2, 2, 2);
    mmap_enc_mat_init(vtable, pp, one_enc_2,  2, 2);
    mmap_enc_mat_init(vtable, pp, result,     1, 2);

    encode(vtable, sk, zero_enc_1, zero_1, 0, 1, 2, rng);
    encode(vtable, sk, one_enc_1,  one_1,  0, 1, 2, rng);
    encode(vtable, sk, zero_enc_2, zero_2, 1, 2, 2, rng);
    encode(vtable, sk, one_enc_2,  one_2,  1, 2, 2, rng);

    printf("* Matrix multiplication\n");
    mmap_enc_mat_mul(vtable, pp, result, zero_enc_1, zero_enc_2);
    ok &= expect("[1 0] * [1 0][0 0]", 1, vtable->enc->is_zero(result->m[0][1], pp));
    mmap_enc_mat_mul(vtable, pp, result, zero_enc_1, one_enc_2);
    ok &= expect("[1 0] * [1 0][0 1]", 1, vtable->enc->is_zero(result->m[0][1], pp));
    mmap_enc_mat_mul(vtable, pp, result, one_enc_1, zero_enc_2);
    ok &= expect("[1 1] * [1 0][0 0]", 1, vtable->enc->is_zero(result->m[0][1], pp));
    mmap_enc_mat_mul(vtable, pp, result, one_enc_1, one_enc_2);
    ok &= expect("[1 1] * [1 0][0 1]", 0, vtable->enc->is_zero(result->m[0][1], pp));

    _fmpz_mat_init_rand(rand, 2, rng, moduli[0]);
    fmpz_layer_mul_right(zero_1, one_1, rand, moduli[0]);
    fmpz_modp_matrix_inverse(rand, rand, 2, moduli[0]);
    fmpz_layer_mul_left(zero_2, one_2, rand, moduli[0]);

    encode(vtable, sk, zero_enc_1, zero_1, 0, 1, 2, rng);
    encode(vtable, sk, one_enc_1,  one_1,  0, 1, 2, rng);
    encode(vtable, sk, zero_enc_2, zero_2, 1, 2, 2, rng);
    encode(vtable, sk, one_enc_2,  one_2,  1, 2, 2, rng);

    printf("* Randomized matrix multiplication\n");
    mmap_enc_mat_mul(vtable, pp, result, zero_enc_1, zero_enc_2);
    ok &= expect("[1 0] * [1 0][0 0]", 1, vtable->enc->is_zero(result->m[0][1], pp));
    mmap_enc_mat_mul(vtable, pp, result, zero_enc_1, one_enc_2);
    ok &= expect("[1 0] * [1 0][0 1]", 1, vtable->enc->is_zero(result->m[0][1], pp));
    mmap_enc_mat_mul(vtable, pp, result, one_enc_1, zero_enc_2);
    ok &= expect("[1 1] * [1 0][0 0]", 1, vtable->enc->is_zero(result->m[0][1], pp));
    mmap_enc_mat_mul(vtable, pp, result, one_enc_1, one_enc_2);
    ok &= expect("[1 1] * [1 0][0 1]", 0, vtable->enc->is_zero(result->m[0][1], pp));

    free(moduli);

    return !ok;
}

static int test_lambdas(const mmap_vtable *vtable, bool is_gghlite)
{
    int err = 0;
    for (int i = 0; i < sizeof(lambdas) / (sizeof(lambdas[0])); ++i) {
        printf("** lambda = %lu\n", lambdas[i]);
        err |= test(vtable, lambdas[i], is_gghlite);
    }
    return err;
}

int main(void)
{
    int err = 0;
    printf("* Dummy\n");
    err |= test_lambdas(&dummy_vtable, false);
    printf("* CLT13\n");
    err |= test_lambdas(&clt_vtable, false);
#ifdef HAVE_GGHLITE
    printf("* GGHLite\n");
    err |= test_lambdas(&gghlite_vtable, true);
#endif
    return err;
}

#else

int main(void)
{
    return 0;
}

#endif

