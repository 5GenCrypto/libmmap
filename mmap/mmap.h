#ifndef _LIBMMAP_MMAP_H_
#define _LIBMMAP_MMAP_H_

#include <gghlite/gghlite-defs.h>
#include <clt13.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mmap_pp {
    union {
        gghlite_params_t gghlite_self;
        clt_pp clt_self;
        mpz_t dummy_self;
    };
};
typedef struct mmap_pp mmap_pp;

struct mmap_sk {
    union {
        gghlite_sk_t gghlite_self;
        clt_state clt_self;
    };
};
typedef struct mmap_sk mmap_sk;

struct mmap_enc {
    union {
        gghlite_enc_t gghlite_self;
        clt_elem_t clt_self;
        mpz_t dummy_self;
    };
};
typedef struct mmap_enc mmap_enc;

/* If we call init or fread, we will call clear. In particular, we will not
 * call clear on the mmap_pp we retrieve from an mmap_sk. */
typedef struct {
    void (*const clear)(mmap_pp *pp);
    void (*const fread)(mmap_pp *const pp, FILE *const fp);
    void (*const fwrite)(const mmap_pp *const pp, FILE *const fp);
    const size_t size;
} mmap_pp_vtable;

typedef struct {
    /* lambda: security parameter
     * kappa: how many multiplications we intend to do
     * gamma: the size of the universe that we will zero-test things at
     */
    void (*const init)(mmap_sk *const sk, size_t lambda, size_t kappa,
                       size_t gamma, unsigned long ncores, aes_randstate_t rng,
                       bool verbose);
    void (*const clear)(mmap_sk *const sk);
    void (*const fread)(mmap_sk *const sk, FILE *const fp);
    void (*const fwrite)(const mmap_sk *const sk, FILE *const fp);
    const mmap_pp * (*const pp)(const mmap_sk *const sk);
    void (*const plaintext_field)(const mmap_sk *const sk, fmpz_t p_out);
    const size_t size;
} mmap_sk_vtable;

typedef struct {
    void (*const init)(mmap_enc *const enc, const mmap_pp *const pp);
    void (*const clear)(mmap_enc *const enc);
    void (*const fread)(mmap_enc *const enc, FILE *const fp);
    void (*const fwrite)(const mmap_enc *const enc, FILE *const fp);
    void (*const set)(mmap_enc *const dest, const mmap_enc *const src);
    void (*const add)(mmap_enc *const dest, const mmap_pp *const pp,
                      const mmap_enc *const a, const mmap_enc *const b);
    /* TODO: sub? */
    void (*const mul)(mmap_enc *const dest, const mmap_pp *const pp,
                      const mmap_enc *const a, const mmap_enc *const b);
    bool (*const is_zero)(const mmap_enc *const enc, const mmap_pp *const pp);
    /* TODO: should this `int *` be `bool *`? */
    void (*const encode)(mmap_enc *const enc, const mmap_sk *const sk, int n,
                         const fmpz_t *plaintext, int *group, aes_randstate_t rng);
    const size_t size;
} mmap_enc_vtable;

typedef struct {
    const mmap_pp_vtable  *const pp;
    const mmap_sk_vtable  *const sk;
    const mmap_enc_vtable *const enc;
} mmap_vtable;
typedef const mmap_vtable *const const_mmap_vtable;

struct _mmap_enc_mat_struct {
    int nrows; // number of rows in the matrix
    int ncols; // number of columns in the matrix
    mmap_enc ***m;
};

typedef struct _mmap_enc_mat_struct mmap_enc_mat_t[1];

void
mmap_enc_mat_init(const_mmap_vtable mmap, const mmap_pp *const params,
                  mmap_enc_mat_t m, int nrows, int ncols);
void
mmap_enc_mat_clear(const_mmap_vtable mmap, mmap_enc_mat_t m);
void
mmap_enc_mat_mul(const_mmap_vtable mmap, const mmap_pp *const params,
                 mmap_enc_mat_t r, mmap_enc_mat_t m1, mmap_enc_mat_t m2);
void
mmap_enc_mat_mul_par(const_mmap_vtable mmap, const mmap_pp *const params,
                     mmap_enc_mat_t r, mmap_enc_mat_t m1, mmap_enc_mat_t m2);

#ifdef __cplusplus
}
#endif

#endif
