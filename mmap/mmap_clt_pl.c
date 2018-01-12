#include "mmap.h"
#include "mmap_clt_pl.h"

#include <clt_pl.h>
#include <gmp.h>

static void
pp_clear(mmap_pp pp)
{
    clt_pl_pp_free(*(clt_pl_pp_t **) pp);
}

static void
pp_fread(mmap_pp pp, FILE *fp)
{
    *(clt_pl_pp_t **) pp = clt_pl_pp_fread(fp);
}

static void
pp_fwrite(const mmap_pp pp, FILE *fp)
{
    clt_pl_pp_fwrite(*(clt_pl_pp_t **) pp, fp);
}

static const mmap_pp_vtable clt_pl_pp_vtable =
  { .clear  = pp_clear
  , .fread  = pp_fread
  , .fwrite = pp_fwrite
  , .size   = sizeof(clt_pl_pp_t *)
  };

static int
state_init(mmap_sk sk, const mmap_sk_params *params_,
           const mmap_sk_opt_params *opts_, size_t ncores,
           aes_randstate_t rng, bool verbose)
{
    int ret = MMAP_OK;
    bool new_pows = false;
    int *pows;
    int flags = CLT_PL_FLAG_NONE;
    if (verbose)
        flags |= CLT_PL_FLAG_VERBOSE;

    if (params_ == NULL)
        return MMAP_ERR;

    pows = params_->pows;
    if (pows == NULL) {
        new_pows = true;
        pows = calloc(params_->gamma, sizeof pows[0]);
        for (size_t i = 0; i < params_->gamma; i++) {
            pows[i] = 1;
        }
    }
    clt_pl_params_t params = {
        .lambda = params_->lambda,
        .nlevels = 0,           /* XXX */
        .nzs = params_->gamma,
        .pows = pows,
    };
    clt_pl_opt_params_t opts = {
        .slots = opts_ ? opts_->nslots : 0,
        .moduli = (opts_ && opts_->modulus) ? opts_->modulus : NULL,
        .nmoduli = opts_ && opts_->modulus ? 1 : 0,
    };
    if ((*(clt_pl_state_t **)sk = clt_pl_state_new(&params, &opts, ncores, flags, rng)) == NULL)
        ret = MMAP_ERR;
    if (new_pows)
        free(pows);
    return ret;
}

static void
state_clear(mmap_sk sk)
{
    clt_pl_state_free(sk);
}

static void
state_fread(mmap_sk sk, FILE *fp)
{
    *(clt_pl_state_t **)sk = clt_pl_state_fread(fp);
}

static void
state_fwrite(const mmap_sk sk, FILE *fp)
{
    clt_pl_state_fwrite(sk, fp);
}

static fmpz_t *
state_get_moduli(const mmap_sk sk)
{
    mpz_t *moduli;
    fmpz_t *fmoduli;
    size_t nslots = clt_pl_state_nslots(sk);

    moduli = clt_pl_state_moduli(sk);
    fmoduli = calloc(nslots, sizeof fmoduli[0]);
    for (size_t i = 0; i < nslots; ++i) {
        fmpz_init(fmoduli[i]);
        fmpz_set_mpz(fmoduli[i], moduli[i]);
    }
    return fmoduli;
}

static mmap_pp
pp_init(const mmap_sk sk)
{
    return clt_pl_pp_new(sk);
}

static size_t
state_nslots(const mmap_sk sk)
{
    return clt_pl_state_nslots(sk);
}

static size_t
state_nzs(const mmap_sk sk)
{
    return clt_pl_state_nzs(sk);
}

static const
mmap_sk_vtable clt_pl_sk_vtable =
  { .init   = state_init
  , .clear  = state_clear
  , .fread  = state_fread
  , .fwrite = state_fwrite
  , .pp     = pp_init
  , .plaintext_fields = state_get_moduli
  , .nslots = state_nslots
  , .nzs = state_nzs
  , .size   = sizeof(clt_pl_state_t *)
  };

static void
enc_init(mmap_enc enc, const mmap_pp pp)
{
    (void) pp;
    *(clt_elem_t **) enc = clt_elem_new();
}

static void
enc_clear(mmap_enc enc)
{
    clt_elem_free(*(clt_elem_t **) enc);
}

static void
enc_fread(mmap_enc enc, FILE *fp)
{
    *(clt_elem_t **) enc = clt_elem_new();
    clt_elem_fread(*(clt_elem_t **) enc, fp);
}

static void
enc_fwrite(const mmap_enc enc, FILE *fp)
{
    clt_elem_fwrite(*(clt_elem_t **) enc, fp);
}

static void
enc_set(mmap_enc dest, const mmap_enc src)
{
    clt_elem_set(*(clt_elem_t **) dest, *(clt_elem_t **) src);
}

static void
enc_add(mmap_enc dest, const mmap_pp pp, const mmap_enc a, const mmap_enc b)
{
    clt_pl_elem_add(*(clt_elem_t **) dest, *(clt_pl_pp_t **) pp, *(clt_elem_t **) a, *(clt_elem_t **) b);
}

static void
enc_sub(const mmap_enc dest, const mmap_pp pp, const mmap_enc a, const mmap_enc b)
{
    clt_pl_elem_sub(*(clt_elem_t **) dest, *(clt_pl_pp_t **) pp, *(clt_elem_t **) a, *(clt_elem_t **) b);
}

static void
enc_mul(const mmap_enc dest, const mmap_pp pp, const mmap_enc a, const mmap_enc b, size_t idx)
{
    clt_pl_elem_mul(*(clt_elem_t **)dest, *(clt_pl_pp_t **) pp, *(clt_elem_t **)a, *(clt_elem_t **)b, idx);
}

static bool
enc_is_zero(const mmap_enc enc, const mmap_pp pp)
{
    return clt_pl_is_zero(*(clt_elem_t **)enc, *(clt_pl_pp_t **) pp);
}

static void
encode(mmap_enc enc, const mmap_sk sk, size_t n,
       const fmpz_t *plaintext, int *group)
{
    mpz_t *ins;

    ins = calloc(n, sizeof ins[0]);
    for (size_t i = 0; i < n; ++i) {
        mpz_init(ins[i]);
        fmpz_get_mpz(ins[i], plaintext[i]);
    }
    clt_pl_encode(*(clt_elem_t **) enc, *(clt_pl_state_t **) sk, n, ins, group);
    for (size_t i = 0; i < n; ++i) {
        mpz_clear(ins[i]);
    }
    free(ins);
}

static void
enc_print(const mmap_enc enc)
{
    clt_elem_print(*(clt_elem_t **) enc);
}

static const mmap_enc_vtable clt_pl_enc_vtable =
  { .init    = enc_init
  , .clear   = enc_clear
  , .fread   = enc_fread
  , .fwrite  = enc_fwrite
  , .set     = enc_set
  , .add     = enc_add
  , .sub     = enc_sub
  , .mul     = enc_mul
  , .is_zero = enc_is_zero
  , .encode  = encode
  , .degree  = NULL
  , .print   = enc_print
  , .size    = sizeof(clt_elem_t *)
  };

const mmap_vtable clt_pl_vtable =
  { .pp  = &clt_pl_pp_vtable
  , .sk  = &clt_pl_sk_vtable
  , .enc = &clt_pl_enc_vtable
  };
