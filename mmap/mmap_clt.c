#include "mmap.h"
#include "mmap_clt.h"

#include <gmp.h>

static void clt_pp_clear_wrapper (mmap_pp *pp)
{
    clt_pp_clear(&(pp->clt_self));
}

static void clt_pp_read_wrapper (mmap_pp *const pp, FILE *const fp)
{
    clt_pp_fread(fp, &(pp->clt_self));
}

static void clt_pp_save_wrapper (const mmap_pp *const pp, FILE *const fp)
{
    clt_pp_fsave(fp, &(pp->clt_self));
}

static const mmap_pp_vtable clt_pp_vtable =
  { .clear  = clt_pp_clear_wrapper
  , .fread  = clt_pp_read_wrapper
  , .fwrite = clt_pp_save_wrapper
  , .size   = sizeof(clt_pp)
  };

static void clt_state_init_wrapper (mmap_sk *const sk, size_t lambda, size_t kappa,
                                    size_t gamma, int *pows, unsigned long ncores,
                                    aes_randstate_t rng, bool verbose)
{
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
    clt_state_init(&sk->clt_self, kappa, lambda, gamma, pows, ncores, flags, rng);
    if (new_pows)
        free(pows);
}

static void clt_state_clear_wrapper (mmap_sk *const sk)
{
    clt_state_clear(&(sk->clt_self));
}

static void clt_state_read_wrapper (mmap_sk *const sk, FILE *const fp)
{
    clt_state_fread(fp, &(sk->clt_self));
}

static void clt_state_save_wrapper (const mmap_sk *const sk, FILE *const fp)
{
    clt_state_fsave(fp, &(sk->clt_self));
}

static fmpz_t * clt_state_get_moduli (const mmap_sk *const sk)
{
    fmpz_t *moduli;

    moduli = calloc(sk->clt_self.n, sizeof(fmpz_t));
    for (size_t i = 0; i < sk->clt_self.n; ++i) {
        fmpz_init(moduli[i]);
        fmpz_set_mpz(moduli[i], sk->clt_self.gs[i]);
    }
    return moduli;
}

static const mmap_pp * clt_pp_init_wrapper (const mmap_sk *const sk)
{
    mmap_pp *pp = malloc(sizeof(mmap_pp));
    clt_pp_init(&(pp->clt_self), &(sk->clt_self));
    return pp;
}

static const mmap_sk_vtable clt_sk_vtable =
  { .init   = clt_state_init_wrapper
  , .clear  = clt_state_clear_wrapper
  , .fread  = clt_state_read_wrapper
  , .fwrite = clt_state_save_wrapper
  , .pp     = clt_pp_init_wrapper
  , .plaintext_fields = clt_state_get_moduli
  , .size   = sizeof(clt_state)
  };

static void clt_enc_init_wrapper (mmap_enc *const enc, const mmap_pp *const pp __attribute__ ((unused)))
{
    clt_elem_init(enc->clt_self);
}

static void clt_enc_clear_wrapper (mmap_enc *const enc)
{
    clt_elem_clear(enc->clt_self);
}

static void clt_enc_fread_wrapper (mmap_enc *const enc, FILE *const fp)
{
    clt_elem_init(enc->clt_self);
    mpz_inp_raw(enc->clt_self, fp);
}

static void clt_enc_fwrite_wrapper (const mmap_enc *const enc, FILE *const fp)
{
    mpz_out_raw(fp, enc->clt_self);
}

static void clt_enc_set_wrapper (mmap_enc *const dest, const mmap_enc *const src)
{
    clt_elem_set(dest->clt_self, src->clt_self);
}

static void clt_enc_add_wrapper (mmap_enc *const dest, const mmap_pp *const pp, const mmap_enc *const a, const mmap_enc *const b)
{
    clt_elem_add(dest->clt_self, &pp->clt_self, a->clt_self, b->clt_self);
}

static void clt_enc_sub_wrapper (mmap_enc *const dest, const mmap_pp *const pp, const mmap_enc *const a, const mmap_enc *const b)
{
    clt_elem_sub(dest->clt_self, &pp->clt_self, a->clt_self, b->clt_self);
}

static void clt_enc_mul_wrapper (mmap_enc *const dest, const mmap_pp *const pp, const mmap_enc *const a, const mmap_enc *const b)
{
    clt_elem_mul(dest->clt_self, &pp->clt_self, a->clt_self, b->clt_self);
}

static bool clt_enc_is_zero_wrapper (const mmap_enc *const enc, const mmap_pp *const pp)
{
    return clt_is_zero(&pp->clt_self, enc->clt_self);
}

static void
clt_encode_wrapper (mmap_enc *const enc, const mmap_sk *const sk, int n,
                    const fmpz_t *plaintext, int *group)
{
    mpz_t *ins;

    ins = calloc(n, sizeof(mpz_t));
    for (int i = 0; i < n; ++i) {
        mpz_init(ins[i]);
        fmpz_get_mpz(ins[i], plaintext[i]);
    }
    clt_encode(enc->clt_self, &sk->clt_self, n, ins, group);
    for (int i = 0; i < n; ++i) {
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
