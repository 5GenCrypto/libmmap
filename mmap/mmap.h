#ifndef _LIBMMAP_MMAP_H_
#define _LIBMMAP_MMAP_H_

#include <aesrand.h>
#include <stdbool.h>
#include <stdio.h> /* for FILE */
#include <flint/fmpz.h>
#include <gmp.h>

#define MMAP_OK 0
#define MMAP_ERR (-1)

#ifdef __cplusplus
extern "C" {
#endif

typedef void *mmap_pp;
typedef void *mmap_sk;
typedef void *mmap_enc;

/* If we call fread, we will call free. In particular, we will not call free
 * on the mmap_pp we retrieve from an mmap_sk. */
typedef struct {
    void (*const free)(const mmap_pp pp);
    mmap_pp (*const fread)(FILE *fp);
    int (*const fwrite)(const mmap_pp pp, FILE *fp);
} mmap_pp_vtable;

typedef struct {
    size_t lambda;              /* security parameter */
    size_t kappa;               /* multilinearity */
    size_t gamma;               /* size of zero-test universe */
    int *pows;
} mmap_sk_params;

typedef struct {
    size_t nslots;              /* number of required slots */
    mpz_t *modulus;             /* plaintext modulus of first slot */
    bool is_polylog;
} mmap_sk_opt_params;

typedef struct {
    mmap_sk (*const new)(const mmap_sk_params *params,
                         const mmap_sk_opt_params *opts, size_t ncores,
                         aes_randstate_t rng, bool verbose);
    void (*const free)(mmap_sk sk);
    mmap_sk (*const fread)(FILE *fp);
    int (*const fwrite)(const mmap_sk sk, FILE *fp);
    mmap_pp (*const pp)(mmap_sk sk);
    mpz_t * (*const plaintext_fields)(const mmap_sk sk);
    size_t (*const nslots)(const mmap_sk sk);
    size_t (*const nzs)(const mmap_sk sk);
} mmap_sk_vtable;

typedef struct {
    mmap_enc (*const new)(const mmap_pp pp);
    void (*const free)(mmap_enc enc);
    mmap_enc (*const fread)(FILE *fp);
    int (*const fwrite)(const mmap_enc enc, FILE *fp);
    void (*const set)(mmap_enc dest, const mmap_enc src);
    int (*const add)(mmap_enc dest, const mmap_pp pp, const mmap_enc a, const mmap_enc b);
    int (*const sub)(mmap_enc dest, const mmap_pp pp, const mmap_enc a, const mmap_enc b);
    int (*const mul)(mmap_enc dest, const mmap_pp pp, const mmap_enc a, const mmap_enc b);
    bool (*const is_zero)(const mmap_enc enc, const mmap_pp pp);
    int (*const encode)(mmap_enc enc, const mmap_sk sk, size_t n,
                        const mpz_t *plaintext, const int *pows, size_t level);
    unsigned int (*const degree)(const mmap_enc enc);
    void (*const print)(const mmap_enc enc);
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
    mmap_enc **m;
};

typedef struct _mmap_enc_mat_struct mmap_enc_mat_t[1];

void
mmap_enc_mat_init(const_mmap_vtable mmap, const mmap_pp params,
                  mmap_enc_mat_t m, int nrows, int ncols);
void
mmap_enc_mat_clear(const_mmap_vtable mmap, mmap_enc_mat_t m);
void
mmap_enc_mat_mul(const_mmap_vtable mmap, const mmap_pp params,
                 mmap_enc_mat_t r, mmap_enc_mat_t m1, mmap_enc_mat_t m2);
void
mmap_enc_mat_mul_par(const_mmap_vtable mmap, const mmap_pp params,
                     mmap_enc_mat_t r, mmap_enc_mat_t m1, mmap_enc_mat_t m2);

#ifdef __cplusplus
}
#endif

#endif
