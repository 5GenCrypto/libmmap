#include "mmap.h"
#include "mmap_clt.h"

#include <clt13.h>
#include <gmp.h>

static void
clt_pp_clear_wrapper(mmap_pp pp)
{
    clt_pp_free(*(clt_pp_t **) pp);
}

static void
clt_pp_fread_wrapper(mmap_pp pp, FILE *fp)
{
    *(clt_pp_t **) pp = clt_pp_fread(fp);
}

static void
clt_pp_fwrite_wrapper(const mmap_pp pp, FILE *fp)
{
    clt_pp_fwrite(*(clt_pp_t **) pp, fp);
}

static const mmap_pp_vtable clt_pp_vtable =
  { .clear  = clt_pp_clear_wrapper
  , .fread  = clt_pp_fread_wrapper
  , .fwrite = clt_pp_fwrite_wrapper
  , .size   = sizeof(clt_pp_t *)
  };

static int
clt_state_init_wrapper(mmap_sk sk, const mmap_sk_params *params_,
                       const mmap_sk_opt_params *opts_, size_t ncores,
                       aes_randstate_t rng, bool verbose)
{
    int ret = MMAP_OK;
    bool new_pows = false;
    int *pows;
    int flags = CLT_FLAG_OPT_CRT_TREE | CLT_FLAG_OPT_PARALLEL_ENCODE;
    if (verbose)
        flags |= CLT_FLAG_VERBOSE;

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
    clt_params_t params = {
        .lambda = params_->lambda,
        .kappa = params_->kappa,
        .nzs = params_->gamma,
        .pows = pows,
    };
    clt_opt_params_t opts = {
        .slots = opts_ ? opts_->nslots : 0,
        .moduli = (opts_ && opts_->modulus) ? opts_->modulus : NULL,
        .nmoduli = opts_ && opts_->modulus ? 1 : 0,
    };
    *(clt_state_t **)sk = clt_state_new(&params, &opts, ncores, flags, rng);
    if (*(clt_state_t **)sk == NULL)
        ret = MMAP_ERR;
    if (new_pows)
        free(pows);
    return ret;
}

static void
clt_state_clear_wrapper(mmap_sk sk)
{
    clt_state_free(*(clt_state_t **) sk);
}

static void
clt_state_fread_wrapper(mmap_sk sk, FILE *fp)
{
    *(clt_state_t **)sk = clt_state_fread(fp);
}

static void
clt_state_fwrite_wrapper(const mmap_sk sk, FILE *fp)
{
    clt_state_fwrite(*(clt_state_t **) sk, fp);
}

static fmpz_t *
clt_state_get_moduli(const mmap_sk sk)
{
    mpz_t *moduli;
    fmpz_t *fmoduli;
    size_t nslots = clt_state_nslots(*(clt_state_t **) sk);

    moduli = clt_state_moduli(*(clt_state_t **) sk);
    fmoduli = calloc(nslots, sizeof fmoduli[0]);
    for (size_t i = 0; i < nslots; ++i) {
        fmpz_init(fmoduli[i]);
        fmpz_set_mpz(fmoduli[i], moduli[i]);
    }
    return fmoduli;
}

static mmap_pp
clt_pp_init_wrapper(const mmap_sk sk)
{
    clt_pp_t **pp = calloc(1, sizeof pp[0]);
    *pp = clt_pp_new(*(clt_state_t **) sk);
    return pp;
}

static size_t
clt_state_nslots_wrapper(const mmap_sk sk)
{
    return clt_state_nslots(*(clt_state_t **) sk);
}

static size_t
clt_state_nzs_wrapper(const mmap_sk sk)
{
    return clt_state_nzs(*(clt_state_t **) sk);
}

static const
mmap_sk_vtable clt_sk_vtable =
  { .init   = clt_state_init_wrapper
  , .clear  = clt_state_clear_wrapper
  , .fread  = clt_state_fread_wrapper
  , .fwrite = clt_state_fwrite_wrapper
  , .pp     = clt_pp_init_wrapper
  , .plaintext_fields = clt_state_get_moduli
  , .nslots = clt_state_nslots_wrapper
  , .nzs = clt_state_nzs_wrapper
  , .size   = sizeof(clt_state_t *)
  };

static void
clt_enc_init_wrapper(mmap_enc enc, const mmap_pp pp)
{
    (void) pp;
    *(clt_elem_t **) enc = clt_elem_new();
}

static void
clt_enc_clear_wrapper(mmap_enc enc)
{
    clt_elem_free(*(clt_elem_t **) enc);
}

static void
clt_enc_fread_wrapper(mmap_enc enc, FILE *fp)
{
    *(clt_elem_t **) enc = clt_elem_new();
    clt_elem_fread(*(clt_elem_t **) enc, fp);
}

static void
clt_enc_fwrite_wrapper(const mmap_enc enc, FILE *fp)
{
    clt_elem_fwrite(*(clt_elem_t **) enc, fp);
}

static void
clt_enc_set_wrapper(mmap_enc dest, const mmap_enc src)
{
    clt_elem_set(*(clt_elem_t **) dest, *(clt_elem_t **) src);
}

static void
clt_enc_add_wrapper(mmap_enc dest, const mmap_pp pp, const mmap_enc a, const mmap_enc b)
{
    clt_elem_add(*(clt_elem_t **) dest, *(clt_pp_t **) pp, *(clt_elem_t **) a, *(clt_elem_t **) b);
}

static void
clt_enc_sub_wrapper(const mmap_enc dest, const mmap_pp pp, const mmap_enc a, const mmap_enc b)
{
    clt_elem_sub(*(clt_elem_t **) dest, *(clt_pp_t **) pp, *(clt_elem_t **) a, *(clt_elem_t **) b);
}

static void
clt_enc_mul_wrapper(const mmap_enc dest, const mmap_pp pp, const mmap_enc a, const mmap_enc b, size_t idx)
{
    (void) idx;
    clt_elem_mul(*(clt_elem_t **)dest, *(clt_pp_t **) pp, *(clt_elem_t **)a, *(clt_elem_t **)b);
}

static bool
clt_enc_is_zero_wrapper(const mmap_enc enc, const mmap_pp pp)
{
    return clt_is_zero(*(clt_elem_t **)enc, *(clt_pp_t **) pp);
}

static void
clt_encode_wrapper(mmap_enc enc, const mmap_sk sk, size_t n,
                   const fmpz_t *plaintext, int *group)
{
    mpz_t *ins;

    ins = calloc(n, sizeof ins[0]);
    for (size_t i = 0; i < n; ++i) {
        mpz_init(ins[i]);
        fmpz_get_mpz(ins[i], plaintext[i]);
    }
    clt_encode(*(clt_elem_t **) enc, *(clt_state_t **) sk, n, ins, group);
    for (size_t i = 0; i < n; ++i) {
        mpz_clear(ins[i]);
    }
    free(ins);
}

static void
clt_print_wrapper(const mmap_enc enc)
{
    clt_elem_print(*(clt_elem_t **) enc);
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
  , .degree  = NULL
  , .print   = clt_print_wrapper
  , .size    = sizeof(clt_elem_t *)
  };

const mmap_vtable clt_vtable =
  { .pp  = &clt_pp_vtable
  , .sk  = &clt_sk_vtable
  , .enc = &clt_enc_vtable
  };
