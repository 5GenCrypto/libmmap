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

const ulong lambdas[] = {8, 16, 24, 32};
bool deterministic;

static int test(const mmap_vtable *mmap, ulong lambda, bool is_gghlite)
{
    const size_t nzs = 10;
    /* const size_t kappa = 2; */
    int pows[nzs], top_level[nzs], ix0[nzs], ix1[nzs];
    aes_randstate_t rng;
    mmap_sk sk1, sk2;
    mmap_pp pp2;
    mmap_enc enc0, enc1, enc;
    fmpz_t x1, x2, zero, one;
    int ok = 1;

    if(deterministic) {
        /* chosen by fair die roll */
        srand(2649794798);
        aes_randinit_seedn(rng, (unsigned char []){
                92,44,135,51,20,243,175,157,99,32,191,224,201,240,59,140,200,
                    118,49,100,80,43,239,243,238,221,92,36,46,133,23,35},
            32, (unsigned char []){}, 0);
    } else {
        srand(time(NULL));
        aes_randinit(rng);
    }

    for (size_t i = 0; i < nzs; i++)
        pows[i] = 1;

    sk1 = malloc(mmap->sk->size);
    sk2 = malloc(mmap->sk->size);
    mmap->sk->init(sk1, lambda, 1, nzs, pows, 0, 0, rng, true);
    mmap->sk->init(sk2, lambda, 2, nzs, pows, 0, 0, rng, true);

    /* Test serialization */
    {
        FILE *f;

        f = tmpfile();
        mmap->sk->fwrite(sk2, f);
        mmap->sk->clear(sk2);
        free(sk2);
        rewind(f);
        sk2 = malloc(mmap->sk->size);
        mmap->sk->fread(sk2, f);
        fclose(f);

        f = tmpfile();
        mmap->pp->fwrite(mmap->sk->pp(sk2), f);
        rewind(f);
        pp2 = malloc(mmap->pp->size);
        mmap->pp->fread(pp2, f);
        fclose(f);
    }
    mmap_ro_pp pp1 = mmap->sk->pp(sk1);

    fmpz_init_set_ui(x1, 0);
    fmpz_init_set_ui(x2, 0);
    while (fmpz_cmp_ui(x1, 0) <= 0) {
        fmpz_t *moduli;
        fmpz_set_ui(x1, rand());
        moduli = mmap->sk->plaintext_fields(sk1);
        fmpz_mod(x1, x1, moduli[0]);
        free(moduli);
    }
    while (fmpz_cmp_ui(x2, 0) <= 0) {
        fmpz_t *moduli;
        fmpz_set_ui(x2, rand());
        moduli = mmap->sk->plaintext_fields(sk2);
        fmpz_mod(x2, x2, moduli[0]);
        free(moduli);
    }

    fmpz_init_set_ui(zero, 0);
    fmpz_init_set_ui(one, 1);

    for (ulong i = 0; i < nzs; i++) {
        top_level[i] = 1;
    }

    enc0 = malloc(mmap->enc->size);
    enc1 = malloc(mmap->enc->size);
    enc = malloc(mmap->enc->size);
    mmap->enc->init(enc0, pp1);
    mmap->enc->init(enc1, pp1);
    mmap->enc->init(enc, pp1);
    {
        /* Test encoding serialization */
        FILE *f = tmpfile();
        mmap->enc->fwrite(enc0, f);
        mmap->enc->clear(enc0);
        rewind(f);
        mmap->enc->fread(enc0, f);
        fclose(f);
    }
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
        mmap->enc->encode(enc0, sk1, 1, &zero, top_level);
        mmap->enc->encode(enc1, sk1, 1, &zero, top_level);
        mmap->enc->add(enc, pp1, enc0, enc1);
        ok &= expect("is_zero(0 + 0)", 1, mmap->enc->is_zero(enc, pp1));

        mmap->enc->encode(enc0, sk1, 1, &zero, top_level);
        mmap->enc->encode(enc1, sk1, 1, &one,  top_level);
        mmap->enc->add(enc, pp1, enc0, enc1);
        ok &= expect("is_zero(0 + 1)", 0, mmap->enc->is_zero(enc, pp1));

        mmap->enc->encode(enc0, sk1, 1, &zero, top_level);
        mmap->enc->encode(enc1, sk1, 1, &x1,   top_level);
        mmap->enc->add(enc, pp1, enc0, enc1);
        ok &= expect("is_zero(0 + x)", 0, mmap->enc->is_zero(enc, pp1));
        /* TODO: why doesn't this make gghlite happy? */
        mmap->enc->encode(enc0, sk1, 1, &x1, top_level);
        mmap->enc->encode(enc1, sk1, 1, &x1, top_level);
        mmap->enc->add(enc, pp1, enc, enc);
        ok &= expect("is_zero(x + x)", 0, mmap->enc->is_zero(enc, pp1));
    }

    mmap->enc->encode(enc0, sk1, 1, &x1, top_level);
    mmap->enc->encode(enc1, sk1, 1, &x1, top_level);
    mmap->enc->sub(enc, pp1, enc0, enc1);
    ok &= expect("is_zero(x - x)", 1, mmap->enc->is_zero(enc, pp1));

    mmap->enc->clear(enc0);
    mmap->enc->clear(enc1);
    mmap->enc->clear(enc);

    mmap->enc->init(enc0, pp2);
    mmap->enc->init(enc1, pp2);
    mmap->enc->init(enc,  pp2);

    if (!is_gghlite) {
        mmap->enc->encode(enc0, sk2, 1, &x2  , ix0);
        mmap->enc->encode(enc1, sk2, 1, &zero, ix1);
        mmap->enc->mul(enc, pp2, enc0, enc1);
        ok &= expect("is_zero(x * 0)", 1, mmap->enc->is_zero(enc, pp2));

        mmap->enc->encode(enc0, sk2, 1, &x2 , ix0);
        mmap->enc->encode(enc1, sk2, 1, &one, ix1);
        mmap->enc->mul(enc, pp2, enc0, enc1);
        ok &= expect("is_zero(x * 1)", 0, mmap->enc->is_zero(enc, pp2));
    }
    
    mmap->enc->encode(enc0, sk2, 1, &x2, ix0);
    mmap->enc->encode(enc1, sk2, 1, &x2, ix1);
    mmap->enc->mul(enc, pp2, enc0, enc1);
    ok &= expect("is_zero(x * x)", 0, mmap->enc->is_zero(enc, pp2));

    mmap->enc->clear(enc0);
    mmap->enc->clear(enc1);
    mmap->enc->clear(enc);
    free(enc0);
    free(enc1);
    free(enc);

    mmap->pp->clear(pp2);
    free(pp2);

    mmap->sk->clear(sk1);
    mmap->sk->clear(sk2);
    free(sk1);
    free(sk2);
    return !ok;
}

static int test_lambdas(const mmap_vtable *vtable, bool is_gghlite)
{
    for (int i = 0; i < sizeof(lambdas) / (sizeof(lambdas[0])); ++i) {
        printf("** lambda = %lu\n", lambdas[i]);
        if (test(vtable, lambdas[i], is_gghlite))
            return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    deterministic = argc > 1;
    printf("* Dummy\n");
    if (test_lambdas(&dummy_vtable, false))
        return 1;
    printf("* CLT13\n");
    if (test_lambdas(&clt_vtable, false))
        return 1;
#ifdef HAVE_LIBGGHLITE
    printf("* GGHLite\n");
    if (test_lambdas(&gghlite_vtable, true))
        return 1;
#endif
    return 0;
}

