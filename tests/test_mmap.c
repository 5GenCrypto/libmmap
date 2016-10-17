#include <mmap.h>
#include <mmap_clt.h>
#include <mmap_gghlite.h>
#include <mmap_dummy.h>
#include <flint/fmpz.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>

#include "utils.h"

const ulong lambdas[] = {8, 16, 24, 32};

static int test(const mmap_vtable *mmap, ulong lambda, bool is_gghlite)
{
    const size_t nzs = 10;
    const size_t kappa = 2;
    int pows[nzs], top_level[nzs], ix0[nzs], ix1[nzs];
    aes_randstate_t rng;
    mmap_sk *sk;
    mmap_pp *pp;
    mmap_enc x0, x1, xp;
    fmpz_t x, zero, one;
    int ok = 1;

    srand(time(NULL));

    aes_randinit(rng);

    for (size_t i = 0; i < nzs; i++)
        pows[i] = 1;

    sk = malloc(mmap->sk->size);
    mmap->sk->init(sk, lambda, kappa, nzs, pows, 0, 0, rng, true);

    {
        // test initialization & serialization
        FILE *sk_f = tmpfile();
        if (sk_f == NULL) {
            fprintf(stderr, "Couldn't open tmp file!\n");
            exit(EXIT_FAILURE);
        }
        mmap->sk->fwrite(sk, sk_f);
        mmap->sk->clear(sk);
        free(sk);
        rewind(sk_f);
        sk = malloc(mmap->sk->size);
        mmap->sk->fread(sk, sk_f);
        fclose(sk_f);
    }

    {
        FILE *pp_f = tmpfile();
        if (pp_f == NULL) {
            fprintf(stderr, "Couldn't open tmp file!\n");
            exit(EXIT_FAILURE);
        }
        pp = (mmap_pp *) mmap->sk->pp(sk);
        mmap->pp->fwrite(pp, pp_f);
        rewind(pp_f);
        pp = malloc(mmap->pp->size);
        mmap->pp->fread(pp, pp_f);
        fclose(pp_f);
    }

    fmpz_init_set_ui(x, 0);
    while (fmpz_cmp_ui(x, 0) <= 0) {
        fmpz_t *moduli;
        fmpz_set_ui(x, rand());
        moduli = mmap->sk->plaintext_fields(sk);
        fmpz_mod(x, x, moduli[0]);
        free(moduli);
    }
    printf("x = ");
    fmpz_print(x);
    printf("\n");

    fmpz_init_set_ui(zero, 0);
    fmpz_init_set_ui(one, 1);

    for (ulong i = 0; i < nzs; i++) {
        top_level[i] = 1;
    }

    mmap->enc->init(&x0, pp);
    mmap->enc->init(&x1, pp);
    mmap->enc->init(&xp, pp);
    for (ulong i = 0; i < nzs; i++) {
        if (i < nzs / 2) {
            ix0[i] = 1;
            ix1[i] = 0;
        } else {
            ix0[i] = 0;
            ix1[i] = 1;
        }
    }

    if (!is_gghlite) {
        mmap->enc->encode(&x0, sk, 1, &zero, top_level);
        mmap->enc->encode(&x1, sk, 1, &zero, top_level);
        mmap->enc->add(&xp, pp, &x0, &x1);
        ok &= expect("is_zero(0 + 0)", 1, mmap->enc->is_zero(&xp, pp));

        mmap->enc->encode(&x0, sk, 1, &zero, top_level);
        mmap->enc->encode(&x1, sk, 1, &one,  top_level);
        mmap->enc->add(&xp, pp, &x0, &x1);
        ok &= expect("is_zero(0 + 1)", 0, mmap->enc->is_zero(&xp, pp));

        mmap->enc->encode(&x0, sk, 1, &zero, top_level);
        mmap->enc->encode(&x1, sk, 1, &x,    top_level);
        mmap->enc->add(&xp, pp, &x0, &x1);
        ok &= expect("is_zero(0 + x)", 0, mmap->enc->is_zero(&xp, pp));

        mmap->enc->encode(&x0, sk, 1, &x   , ix0);
        mmap->enc->encode(&x1, sk, 1, &zero, ix1);
        mmap->enc->mul(&xp, pp, &x0, &x1);
        ok &= expect("is_zero(x * 0)", 1, mmap->enc->is_zero(&xp, pp));

        mmap->enc->encode(&x0, sk, 1, &x  , ix0);
        mmap->enc->encode(&x1, sk, 1, &one, ix1);
        mmap->enc->mul(&xp, pp, &x0, &x1);
        ok &= expect("is_zero(x * 1)", 0, mmap->enc->is_zero(&xp, pp));
    }

    mmap->enc->encode(&x0, sk, 1, &x, ix0);
    mmap->enc->encode(&x1, sk, 1, &x, ix1);
    mmap->enc->mul(&xp, pp, &x0, &x1);
    ok &= expect("is_zero(x * x)", 0, mmap->enc->is_zero(&xp, pp));

    /* mmap->enc->encode(&x0, sk, 1, x, ix0); */
    /* mmap->enc->encode(&x1, sk, 1, x, ix1); */
    /* mmap->enc->sub(&xp, pp, &x0, &x1); */
    /* ok &= expect("is_zero(x - x)", 1, mmap->enc->is_zero(&xp, pp)); */

    mmap->enc->encode(&x0, sk, 1, &x, ix0);
    mmap->enc->encode(&x1, sk, 1, &x, ix1);
    mmap->enc->add(&xp, pp, &x0, &x1);
    ok &= expect("is_zero(x + x)", 0, mmap->enc->is_zero(&xp, pp));

    mmap->enc->clear(&x0);
    mmap->enc->clear(&x1);
    mmap->enc->clear(&xp);
    free(sk);
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
    printf("* GGHLite\n");
    err |= test_lambdas(&gghlite_vtable, true);
    return err;
}

