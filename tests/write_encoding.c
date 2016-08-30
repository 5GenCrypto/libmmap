#include <mmap.h>
#include <mmap_clt.h>
#include <mmap_gghlite.h>
#include <flint/fmpz.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>

int main(int argc, char **argv)
{
    const mmap_vtable *const mmap = &clt_vtable;
    /* const mmap_vtable *const mmap = &gghlite_vtable; */

    ulong lambda = atoi(argv[1]);
    ulong kappa  = atoi(argv[2]);
    ulong nzs    = kappa;

    aes_randstate_t rng;
    aes_randinit(rng);

    mmap_sk *sk = malloc(mmap->sk->size);
    mmap->sk->init(sk, lambda, kappa, nzs, 1, rng, false);
    const mmap_pp *const pp = mmap->sk->pp(sk);

    mmap_enc x;
    mmap->enc->init(&x, pp);

    for (int i = 0; i < kappa; i++) {
        fmpz_t pt [1];
        fmpz_init_set_ui(pt[0], 10);

        int ix [nzs];
        for (int j = 0; j < nzs; j++) {
            ix[j] = i == j;
        }

        if (i == 0) {
            mmap->enc->encode(&x, sk, 1, pt, ix, rng);
        } else {
            mmap_enc y;
            mmap->enc->init(&y, pp);
            mmap->enc->encode(&y, sk, 1, pt, ix, rng);
            mmap->enc->mul(&x, pp, &x, &y);
        }
    }

    FILE *fp = fopen("encoding.bin", "w+");
    if (fp == NULL) {
        fprintf(stderr, "Couldn't open encoding.bin!\n");
        exit(1);
    }

    mmap->enc->fwrite(&x, fp);
    return 0;
}
