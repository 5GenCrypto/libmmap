# libmmap - Multilinear map library

`libmmap` provides a unified API for multilinear map operations and three implementations of the API. The API is organized in an object-oriented style. There are three objects of interest:

* Secret keys
* Public parameters/keys
* Encodings

The general flow for using these operations is to do a key generation operation, which produces both a secret key and a public key; use the secret key to produce some encodings; then use the public key to do arithmetic and zero-testing on the encodings. Our library also provides some facilities for disk serialization and deserialization.

There are three extant implementations of the API, backed by the gghlite library, the libclt library, and an insecure dummy implementation which stores and operates on plaintexts intended for debugging use only.

## Object system

We use a simplified object-oriented-like system. Each object consists of a C struct (which should be viewed as opaque to consumers of the API) together with a vtable containing function pointers (which are permitted to poke at the internals of the struct). For example, the public key object is modeled by this snippet from [`mmap.h`](mmap/mmap.h):

    struct mmap_pp { /* unimportant implementation details elided */ };
    typedef struct mmap_pp mmap_pp;

    typedef struct {
      void (*const clear)(mmap_pp *);
      void (*const fread)(mmap_pp *, FILE *);
      void (*const fwrite)(const mmap_pp *, FILE *);
      const size_t size;
    } mmap_pp_vtable;

Thus public keys support writing to disk (via `fwrite`), reading from disk (via `fread`), destruction (via `clear`). By convention, the first argument to each method is the instance to invoke that method on.

Some methods are common to several different objects:

* `size` (not actually a method, but a field common to all objects) tells how many bytes the associated struct takes. It exists for historical reasons, and is defined to be the `sizeof` the appropriate struct.
* `init` initializes an instance from the remaining arguments.
* `clear` destroys an instance, deallocating any memory reserved during `init` or other operations.
* `fread` initializes an instance from disk. For simplicity, it exits the program if parsing fails.
* `fwrite` serializes an instance to disk.

In general, this means the usage pattern should be to call `init` or `fread` on a chunk of at least `size` bytes; do some other operations; then call `clear` when the program is finished with the instance.

## Public keys

Public keys have no object-specific methods; they exist primarily to be parameters to other objects' methods.

Additionally, they have no `init` method, and so some public keys should not be `clear`ed! In particular, public keys read from disk with `fread` should be, but public keys retrieved from a private key via the private key's `pp` method should not be.

The full interface is given in `mmap/mmap.h` by `mmap_pp_vtable`:

    typedef struct {
      void (*const clear)(mmap_pp *);
      void (*const fread)(mmap_pp *, FILE *);
      void (*const fwrite)(const mmap_pp *, FILE *);
      const size_t size;
    } mmap_pp_vtable;

## Private keys

Private keys offer key generation via their `init` operation, which has this type:

    void (*const init)(mmap_sk *, size_t, size_t, size_t, unsigned long, aes_randstate_t, bool);

The arguments to this method are:
* the security parameter (lambda),
* how many multiplications need to be supported (kappa),
* the size of the universe that the zero-test operates at (gamma),
* how much parallelism to use,
* a random seed (which will be modified in-place during the method call), and
* a verbosity level.

The `pp` method returns the associated public key. As noted in the section on public keys, the public keys acquired from this method (rather than via the public key's `fread` method) should not be `clear`ed.

By assumption, plaintexts to be encoded with this key are drawn from Z/p for some prime p. You can ask what prime via the `plaintext_field` method, which overwrites its second argument with p.

The full interface is given by `mmap_sk_vtable`:

    typedef struct {
      void (*const init)(mmap_sk *, size_t, size_t, size_t, unsigned long, aes_randstate_t, bool);
      void (*const clear)(mmap_sk *);
      void (*const fread)(mmap_sk *c, FILE *);
      void (*const fwrite)(const mmap_sk *, FILE *);
      const size_t size;

      const mmap_pp *const (*const pp)(const mmap_sk *);
      void (*const plaintext_field)(const mmap_sk *, fmpz_t);
    } mmap_sk_vtable;

## Encodings

Encodings can be added (with `add`), multiplied (with `mul`), and copied (with `set`). In all cases, the instance supplied as the first parameter is overwritten with the result of the operation. Zero-testing can be performed with the `is_zero` method.

It is assumed that the encodings passed to `add` have the same set of tags (in which case the result will also have this set of tags), and that the encodings passed to `mul` have disjoint sets of tags (in which case the result will be tagged with the union of these two sets). This property is not checked.

If you have access to the secret key, you can also produce fresh encodings of plaintexts with the `encode` method, which has this type:

    void (*const encode)(mmap_enc *, const mmap_sk *, int, const fmpz_t *, int *, aes_randstate_t);

The arguments to this method are:

* the secret key,
* the number of plaintexts to encode (assuming the backend supports multiple-slot plaintexts),
* the plaintexts themselves in an array whose length is given by the previous argument,
* an array of `0`s and `1`s as long as the universe specified during key generation, telling which tags in the universe should be applied to the encoding, and
* a random seed (which will be modified in-place during the method call).

The full interface is given by `mmap_enc_vtable`:

    typedef struct {
      void (*const init)(mmap_enc *, const mmap_pp *);
      void (*const clear)(mmap_enc *);
      void (*const fread)(mmap_enc *, FILE *);
      void (*const fwrite)(const mmap_enc *, FILE *);
      const size_t size;

      void (*const set)(mmap_enc *, const mmap_enc *);
      void (*const add)(mmap_enc *, const mmap_pp *, const mmap_enc *, const mmap_enc *);
      void (*const mul)(mmap_enc *, const mmap_pp *, const mmap_enc *, const mmap_enc *);
      bool (*const is_zero)(const mmap_enc *, const mmap_pp *);
      void (*const encode)(mmap_enc *, const mmap_sk *, int, const fmpz_t *, int *, aes_randstate_t);
    } mmap_enc_vtable;

## Miscellaneous

For convenience, we provide a top-level `mmap_vtable` type which contains a vtable for each kind of object. The three extant implementations each provide a value of this type: [`mmap_clt.h`](mmap/mmap_clt.h) provides `clt_vtable`, [`mmap_gghlite.h`](mmap/mmap_gghlite.h) provides `gghlite_vtable`, and [`mmap_dummy.h`](mmap/mmap_dummy.h) provides `dummy_vtable`.

We also implement a few matrix-like operations on encodings. The implementation uses the naive O(m\*n\*p) algorithm for multiplication, calling the encoding object's `mul` and `add` methods as appropriate. For historical reasons, the interface to these operations does not use the object-oriented style described above. The `mmap.h` header has the complete interface, which includes little more than the `init`, `clear`, and `mul` methods one might expect:

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
