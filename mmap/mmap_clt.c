#include "mmap.h"
#include "mmap_clt.h"

#include <clt13.h>
#include <gmp.h>

static void clt_pp_clear_wrapper(mmap_pp pp)
{
    clt_pp_delete(*(clt_pp **)pp);
}

static void clt_pp_fread_wrapper(const mmap_pp pp, FILE *const fp)
{
    *(clt_pp **)pp = clt_pp_fread(fp);
}

static void clt_pp_fsave_wrapper(const mmap_ro_pp pp, FILE *const fp)
{
    clt_pp_fwrite(*(clt_pp *const *const)pp, fp);
}

static const mmap_pp_vtable clt_pp_vtable =
  { .clear  = clt_pp_clear_wrapper
  , .fread  = clt_pp_fread_wrapper
  , .fwrite = clt_pp_fsave_wrapper
  , .size   = sizeof(clt_pp *)
  };

static int
clt_state_init_wrapper(const mmap_sk sk, size_t lambda, size_t kappa,
                       size_t gamma, int *pows, size_t nslots, size_t ncores,
                       aes_randstate_t rng, bool verbose)
{
    int ret = MMAP_OK;
    bool new_pows = false;
    int flags = CLT_FLAG_OPT_CRT_TREE | CLT_FLAG_OPT_PARALLEL_ENCODE;
    if (verbose)
        flags |= CLT_FLAG_VERBOSE;

    if (pows == NULL) {
        new_pows = true;
        pows = calloc(gamma, sizeof(int));
        for (size_t i = 0; i < gamma; i++) {
            pows[i] = 1;
        }
    }
    *(clt_state **)sk = clt_state_new(kappa, lambda, gamma, pows, nslots, ncores,
                                 flags, rng);
    if (*(clt_state **)sk == NULL)
        ret = MMAP_ERR;
    if (new_pows)
        free(pows);
    return ret;
}

static void clt_state_clear_wrapper(const mmap_sk sk)
{
    clt_state_delete(*(clt_state **)sk);
}

static void clt_state_read_wrapper(const mmap_sk sk, FILE *const fp)
{
    *(clt_state **)sk = clt_state_fread(fp);
}

static void clt_state_save_wrapper(const mmap_ro_sk sk, FILE *const fp)
{
    clt_state_fwrite(*(clt_state *const *const)sk, fp);
}

static fmpz_t * clt_state_get_moduli(const mmap_ro_sk sk)
{
    mpz_t *moduli;
    fmpz_t *fmoduli;
    size_t nslots = clt_state_nslots(*(clt_state *const *const)sk);

    moduli = clt_state_moduli(*(clt_state *const *const)sk);
    fmoduli = calloc(nslots, sizeof(fmpz_t));
    for (size_t i = 0; i < nslots; ++i) {
        fmpz_init(fmoduli[i]);
        fmpz_set_mpz(fmoduli[i], moduli[i]);
    }
    return fmoduli;
}

static mmap_ro_pp clt_pp_init_wrapper(const mmap_ro_sk sk)
{
    clt_pp * *const pp = malloc(sizeof(clt_pp *));
    *pp = clt_pp_new(*(clt_state *const *const)sk);
    return pp;
}

static size_t clt_state_nslots_wrapper(const mmap_ro_sk sk)
{
    return clt_state_nslots(*(clt_state *const *const)sk);
}

static size_t clt_state_nzs_wrapper(const mmap_ro_sk sk)
{
    return clt_state_nzs(*(clt_state *const *const)sk);
}

static const mmap_sk_vtable clt_sk_vtable =
  { .init   = clt_state_init_wrapper
  , .clear  = clt_state_clear_wrapper
  , .fread  = clt_state_read_wrapper
  , .fwrite = clt_state_save_wrapper
  , .pp     = clt_pp_init_wrapper
  , .plaintext_fields = clt_state_get_moduli
  , .nslots = clt_state_nslots_wrapper
  , .nzs = clt_state_nzs_wrapper
  , .size   = sizeof(clt_state *)
  };

static void clt_enc_init_wrapper (const mmap_enc enc, const mmap_ro_pp pp)
{
    (void) pp;
    clt_elem_init(enc);
}

static void clt_enc_clear_wrapper (const mmap_enc enc)
{
    clt_elem_clear(enc);
}

static void clt_enc_fread_wrapper (const mmap_enc enc, FILE *const fp)
{
    clt_elem_init(enc);
    mpz_inp_raw(enc, fp);
}

static void clt_enc_fwrite_wrapper (const mmap_ro_enc enc, FILE *const fp)
{
    mpz_out_raw(fp, enc);
}

static void clt_enc_set_wrapper (const mmap_enc dest, const mmap_ro_enc src)
{
    clt_elem_set(dest, src);
}

static void clt_enc_add_wrapper (const mmap_enc dest, const mmap_ro_pp pp, const mmap_ro_enc a, const mmap_ro_enc b)
{
    clt_elem_add(dest, *(clt_pp *const *const)pp, a, b);
}

static void clt_enc_sub_wrapper (const mmap_enc dest, const mmap_ro_pp pp, const mmap_ro_enc a, const mmap_ro_enc b)
{
    clt_elem_sub(dest, *(clt_pp *const *const)pp, a, b);
}

static void clt_enc_mul_wrapper (const mmap_enc dest, const mmap_ro_pp pp, const mmap_ro_enc a, const mmap_ro_enc b)
{
    clt_elem_mul(dest, *(clt_pp *const *const)pp, a, b);
}

static bool clt_enc_is_zero_wrapper (const mmap_ro_enc enc, const mmap_ro_pp pp)
{
    return clt_is_zero(enc, *(clt_pp *const *const)pp);
}

static void
clt_encode_wrapper(const mmap_enc enc, const mmap_ro_sk sk, size_t n,
                   const fmpz_t *plaintext, int *group)
{
    mpz_t *ins;

    ins = calloc(n, sizeof(mpz_t));
    for (size_t i = 0; i < n; ++i) {
        mpz_init(ins[i]);
        fmpz_get_mpz(ins[i], plaintext[i]);
    }
    clt_encode(enc, *(clt_state *const *const)sk, n, ins, group);
    for (size_t i = 0; i < n; ++i) {
        mpz_clear(ins[i]);
    }
    free(ins);
}

static const mmap_enc_vtable clt_enc_vtable =
  { .init    = clt_enc_init_wrapper
  , .clear   = clt_enc_clear_wrapper
  , .fread   = clt_enc_fread_wrapper
  , .fwrite  = clt_enc_fwrite_wrapper
  , .set     = clt_enc_set_wrapper
  , .add     = clt_enc_add_wrapper
  , .sub     = clt_enc_sub_wrapper
  , .mul     = clt_enc_mul_wrapper
  , .is_zero = clt_enc_is_zero_wrapper
  , .encode  = clt_encode_wrapper
  , .size    = sizeof(clt_elem_t)
  };

const mmap_vtable clt_vtable =
  { .pp  = &clt_pp_vtable
  , .sk  = &clt_sk_vtable
  , .enc = &clt_enc_vtable
  };
