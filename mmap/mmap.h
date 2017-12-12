#ifndef _LIBMMAP_MMAP_H_
#define _LIBMMAP_MMAP_H_

#include <aesrand/aesrand.h>
#include <stdbool.h>
#include <stdio.h> /* for FILE */
#include <gmp.h>

#define MMAP_OK 0
#define MMAP_ERR (-1)

#ifdef __cplusplus
extern "C" {
#endif


typedef void *mmap_pp;
typedef void *mmap_sk;
typedef void *mmap_enc;

/* read-only versions */
typedef const void *mmap_ro_pp;
typedef const void *mmap_ro_sk;
typedef const void *mmap_ro_enc;

/* If we call fread, we will call clear. In particular, we will not call clear
 * on the mmap_pp we retrieve from an mmap_sk. */
typedef struct {
    void (*const clear)(const mmap_pp pp);
    void (*const fread)(const mmap_pp pp, FILE *fp);
    void (*const fwrite)(const mmap_pp pp, FILE *fp);
    const size_t size;
} mmap_pp_vtable;

typedef struct {
    /* lambda: security parameter
     * kappa: how many multiplications we intend to do
     * gamma: the size of the universe that we will zero-test things at
     */
    int (*const init)(mmap_sk sk, size_t lambda, size_t kappa,
                      size_t gamma, int *pows, size_t nslots, size_t ncores,
                      aes_randstate_t rng, bool verbose);
    void (*const clear)(mmap_sk sk);
    void (*const fread)(mmap_sk sk, FILE *fp);
    void (*const fwrite)(const mmap_sk sk, FILE *fp);
    mmap_pp (*const pp)(const mmap_sk sk);
    fmpz_t * (*const plaintext_fields)(const mmap_sk sk);
    size_t (*const nslots)(const mmap_sk sk);
    size_t (*const nzs)(const mmap_sk sk);
    const size_t size;
} mmap_sk_vtable;

typedef struct {
    void (*const init)(mmap_enc enc, const mmap_pp pp);
    void (*const clear)(mmap_enc enc);
    void (*const fread)(mmap_enc enc, FILE *fp);
    void (*const fwrite)(const mmap_enc enc, FILE *fp);
    void (*const set)(mmap_enc dest, const mmap_enc src);
    void (*const add)(mmap_enc dest, const mmap_pp pp, const mmap_enc a, const mmap_enc b);
    void (*const sub)(mmap_enc dest, const mmap_pp pp, const mmap_enc a, const mmap_enc b);
    void (*const mul)(mmap_enc dest, const mmap_pp pp, const mmap_enc a, const mmap_enc b);
    bool (*const is_zero)(const mmap_enc enc, const mmap_pp pp);
    void (*const encode)(mmap_enc enc, const mmap_sk sk, size_t n, const fmpz_t *plaintext, int *group);
    unsigned int (*const degree)(const mmap_enc enc);
    void (*const print)(const mmap_enc enc);
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
