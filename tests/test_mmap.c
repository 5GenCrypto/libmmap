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
    srand(time(NULL));

    ulong nzs     = 10;
    ulong kappa   = 2;

    aes_randstate_t rng;
    aes_randinit(rng);

    int pows [nzs];
    for (ulong i = 0; i < nzs; i++) pows[i] = 1;

    FILE *sk_f = tmpfile();
    if (sk_f == NULL) {
        fprintf(stderr, "Couldn't open test.map!\n");
        exit(1);
    }

    FILE *pp_f = tmpfile();
    if (pp_f == NULL) {
        fprintf(stderr, "Couldn't open test.pp!\n");
        exit(1);
    }

    // test initialization & serialization
    mmap_sk *sk = malloc(mmap->sk->size);
    mmap->sk->init(sk, lambda, kappa, nzs, NULL, 0, rng, true);

    mmap->sk->fwrite(sk, sk_f);
    mmap->sk->clear(sk);
    free(sk);

    rewind(sk_f);

    sk = malloc(mmap->sk->size);
    mmap->sk->fread(sk, sk_f);

    const mmap_pp *pp_ = mmap->sk->pp(sk);
    mmap->pp->fwrite(pp_, pp_f);
    rewind(pp_f);
    mmap_pp *pp = malloc(mmap->pp->size);
    mmap->pp->fread(pp, pp_f);

    fmpz_t x [1];
    fmpz_init_set_ui(x[0], 0);
    while (fmpz_cmp_ui(x[0], 0) <= 0) {
        fmpz_t *moduli;
        fmpz_set_ui(x[0], rand());
        moduli = mmap->sk->plaintext_fields(sk);
        fmpz_mod(x[0], x[0], moduli[0]);
        free(moduli);
    }
    printf("x = ");
    fmpz_print(x[0]);
    puts("");

    fmpz_t zero [1];
    fmpz_init_set_ui(zero[0], 0);

    fmpz_t one [1];
    fmpz_init_set_ui(one[0], 1);

    int top_level [nzs];
    for (ulong i = 0; i < nzs; i++) {
        top_level[i] = 1;
    }

    int ok = 1;

    mmap_enc x0, x1, xp;
    mmap->enc->init(&x0, pp);
    mmap->enc->init(&x1, pp);
    mmap->enc->init(&xp, pp);
    int ix0 [nzs];
    int ix1 [nzs];
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
        mmap->enc->encode(&x0, sk, 1, zero, top_level);
        mmap->enc->encode(&x1, sk, 1, zero, top_level);
        mmap->enc->add(&xp, pp, &x0, &x1);
        ok &= expect("is_zero(0 + 0)", 1, mmap->enc->is_zero(&xp, pp));

        mmap->enc->encode(&x0, sk, 1, zero, top_level);
        mmap->enc->encode(&x1, sk, 1, one,  top_level);
        mmap->enc->add(&xp, pp, &x0, &x1);
        ok &= expect("is_zero(0 + 1)", 0, mmap->enc->is_zero(&xp, pp));

        mmap->enc->encode(&x0, sk, 1, zero, top_level);
        mmap->enc->encode(&x1, sk, 1, x,    top_level);
        mmap->enc->add(&xp, pp, &x0, &x1);
        ok &= expect("is_zero(0 + x)", 0, mmap->enc->is_zero(&xp, pp));

        mmap->enc->encode(&x0, sk, 1, x   , ix0);
        mmap->enc->encode(&x1, sk, 1, zero, ix1);
        mmap->enc->mul(&xp, pp, &x0, &x1);
        ok &= expect("is_zero(x * 0)", 1, mmap->enc->is_zero(&xp, pp));

        mmap->enc->encode(&x0, sk, 1, x  , ix0);
        mmap->enc->encode(&x1, sk, 1, one, ix1);
        mmap->enc->mul(&xp, pp, &x0, &x1);
        ok &= expect("is_zero(x * 1)", 0, mmap->enc->is_zero(&xp, pp));
    }

    mmap->enc->encode(&x0, sk, 1, x, ix0);
    mmap->enc->encode(&x1, sk, 1, x, ix1);
    mmap->enc->mul(&xp, pp, &x0, &x1);
    ok &= expect("is_zero(x * x)", 0, mmap->enc->is_zero(&xp, pp));

    /* mmap->enc->encode(&x0, sk, 1, x, ix0); */
    /* mmap->enc->encode(&x1, sk, 1, x, ix1); */
    /* mmap->enc->sub(&xp, pp, &x0, &x1); */
    /* ok &= expect("is_zero(x - x)", 1, mmap->enc->is_zero(&xp, pp)); */

    mmap->enc->encode(&x0, sk, 1, x, ix0);
    mmap->enc->encode(&x1, sk, 1, x, ix1);
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

