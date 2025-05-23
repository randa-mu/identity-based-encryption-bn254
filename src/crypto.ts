import {Fp, Fp12, Fp2} from "@noble/curves/abstract/tower"
import {AffinePoint, ProjPointType} from "@noble/curves/abstract/weierstrass"
import {createHasher, expand_message_xmd, expand_message_xof, hash_to_field} from "@noble/curves/abstract/hash-to-curve"
import {CHash} from "@noble/curves/abstract/utils"
import {keccak_256} from "@noble/hashes/sha3"

import {bn254, htfDefaultsG1, mapToG1} from "./bn254"
import {xor} from "./util"

export type G1 = AffinePoint<Fp>
export type G2 = AffinePoint<Fp2>
export type GT = Fp12

export interface Ciphertext {
    U: G2,
    V: Uint8Array
    W: Uint8Array
}

// Various options used to customize the IBE scheme
export type IbeOpts = {
    hash: CHash,                // hash function
    k: number,                  // k-bit collision resistance of hash
    expand_fn: "xmd" | "xof",   // "xmd": expand_message_xmd, "xof": expand_message_xof, see RFC9380, Section 5.3.
    dsts: DstOpts,
}

// Various DSTs used throughout the IBE scheme
export type DstOpts = {
    H1_G1: Uint8Array,
    H2: Uint8Array,
    H3: Uint8Array,
    H4: Uint8Array,
}

const textEncoder = new TextEncoder()
// Default IBE options.
export const DEFAULT_OPTS: IbeOpts = {
    hash: keccak_256,
    k: 128,
    expand_fn: "xmd",
    dsts: {
        H1_G1: textEncoder.encode("IBE_BN254G1_XMD:KECCAK-256_SVDW_RO_H1_"),
        H2: textEncoder.encode("IBE_BN254_XMD:KECCAK-256_H2_"),
        H3: textEncoder.encode("IBE_BN254_XMD:KECCAK-256_H3_"),
        H4: textEncoder.encode("IBE_BN254_XMD:KECCAK-256_H4_"),
    }
}

// Our H4 hash function can output at most 2**16 - 1 = 65535 pseudorandom bytes.
const H4_MAX_OUTPUT_LEN: number = 65535

/*
 * Convert the identity into a point on the curve.
 */
export function createIdentity(identity: Uint8Array, opts: IbeOpts): ProjPointType<Fp> {
    return hashIdentityToG1(identity, opts)
}

/*
 * Encryption function for IBE based on https://www.iacr.org/archive/crypto2001/21390212.pdf Section 6 / https://eprint.iacr.org/2023/189.pdf, Algorithm 1
 * with the identity on G1, and the master public key on G2.
 */
export function encrypt(m: Uint8Array, identity: ProjPointType<Fp>, publicKey: G2, opts: IbeOpts): Ciphertext {
    // We can encrypt at most 2**16 - 1 = 65535 bytes with our H4 hash function.
    const n_bytes = m.length
    if (n_bytes > H4_MAX_OUTPUT_LEN) {
        throw new Error(`cannot encrypt messages larger than our hash output: ${H4_MAX_OUTPUT_LEN} bytes.`)
    }

    // Compute the identity"s public key on G1
    // 3: PK_\rho \gets e(H_1(\rho), P)
    const pk_g2p = bn254.G2.ProjectivePoint.fromAffine(publicKey)
    const pk_rho = bn254.pairing(identity, pk_g2p)

    // Sample a one-time key
    // 4: \sigma \getsr \{0,1\}^\ell
    const sigma = new Uint8Array(32);
    crypto.getRandomValues(sigma)

    // Derive an ephemeral keypair
    // 5: r \gets H_3(\sigma, M)
    const r = hashSigmaMToField(sigma, m, opts)
    // 6: U \gets [r]G_2
    const u_g2 = bn254.G2.ProjectivePoint.BASE.multiply(r).toAffine()

    // Hide the one-time key
    // 7: V \gets \sigma \xor H_2((PK_\rho)^r)
    const sharedKey = bn254.fields.Fp12.pow(pk_rho, r)
    const v = xor(sigma, hashToBytes(sharedKey, sigma.length, opts))

    // Encrypt message m using a hash-based stream cipher with key \sigma
    // 8: W \gets M \xor H_4(\sigma)
    const w = xor(m, hashSigmaToBytes(sigma, n_bytes, opts))

    // 9: return ciphertext
    return {
        U: u_g2,
        V: v,
        W: w
    }
}

/*
 * Decryption function for IBE based on https://www.iacr.org/archive/crypto2001/21390212.pdf Section 6 / https://eprint.iacr.org/2023/189.pdf, Algorithm 1
 * with the identity on G1, and the master public key on G2.
 */
export function decrypt(ciphertext: Ciphertext, decryptionKey: G1, opts: IbeOpts = DEFAULT_OPTS): Uint8Array {
    // Get the one-time decryption key
    const key = preprocessDecryptionKey(ciphertext, decryptionKey, opts)
    return decryptWithPreprocess(ciphertext, key, opts)
}

/**
 * Decryption function for IBE based on https://www.iacr.org/archive/crypto2001/21390212.pdf Section 6 / https://eprint.iacr.org/2023/189.pdf, Algorithm 1
 * with the identity on G1, and the master public key on G2.
 */
export function decryptWithPreprocess(ciphertext: Ciphertext, preprocessedDecryptionKey: Uint8Array, opts: IbeOpts = DEFAULT_OPTS): Uint8Array {
    // Check well-formedness of the ciphertext
    if (ciphertext.W.length > H4_MAX_OUTPUT_LEN) {
        throw new Error(`cannot decrypt messages larger than our hash output: ${H4_MAX_OUTPUT_LEN} bytes.`)
    }
    if (ciphertext.V.length !== opts.hash.outputLen) {
        throw new Error(`cannot decrypt encryption key of invalid length != ${opts.hash.outputLen} bytes.`)
    }
    if (ciphertext.V.length !== preprocessedDecryptionKey.length) {
        throw new Error(`preprocessed decryption key of invalid length`)
    }

    // \ell = min(len(w), opts.hash.outputLen)
    const ell_bytes = ciphertext.W.length

    // Get the one-time decryption key
    // 3: \sigma" \gets V \xor H_2(e(\pi_\rho, U))
    const sigma2 = xor(ciphertext.V, preprocessedDecryptionKey)

    // Decrypt the message
    // 4: M" \gets W \xor H_4(\sigma")
    const m2 = xor(ciphertext.W, hashSigmaToBytes(sigma2, ell_bytes, opts))

    // Derive the ephemeral keypair with the candidate \sigma"
    // 5: r \gets H_3(\sigma, M)
    const r = hashSigmaMToField(sigma2, m2, opts)

    // Verify that \sigma" is consistent with the message and ephemeral public key
    // 6: if U = [r]G_2 then return M" else return \bot
    const u_g2 = bn254.G2.ProjectivePoint.BASE.multiply(r)
    if (bn254.G2.ProjectivePoint.fromAffine(ciphertext.U).equals(u_g2)) {
        return m2
    } else {
        throw new Error("invalid proof: rP check failed")
    }
}

/**
 * Preprocess a signature by computing the hash of the pairing, i.e.,
 * H_2(e(\pi_\rho, U)).
 * @param ciphertext ciphertext to preprocess the decryption key for
 * @param decryptionKey decryption key on g1 for the ciphertext
 * @param opts IBE scheme options
 * @returns preprocessed decryption key
 */
export function preprocessDecryptionKey(ciphertext: Ciphertext, decryptionKey: G1, opts: IbeOpts = DEFAULT_OPTS): Uint8Array {
    const u_g2p = bn254.G2.ProjectivePoint.fromAffine(ciphertext.U)
    u_g2p.assertValidity() // throws an error if point is invalid

    // Derive the shared key using the decryption key and the ciphertext"s ephemeral public key
    const decryptionKeyPoint = bn254.G1.ProjectivePoint.fromAffine(decryptionKey)
    const sharedKey = bn254.pairing(decryptionKeyPoint, u_g2p)

    // Return the mask H_2(e(\pi_\rho, U))
    return hashToBytes(sharedKey, ciphertext.V.length, opts)
}

// Concrete instantiation of H_1 that outputs a point on G1
// H_1: \{0, 1\}^\ast \rightarrow G_1
export function hashIdentityToG1(identity: Uint8Array, opts: IbeOpts): ProjPointType<Fp>{
    const hasher = createHasher(bn254.G1.ProjectivePoint, mapToG1, {
        p: htfDefaultsG1.p,
        m: htfDefaultsG1.m,
        hash: opts.hash,
        k: opts.k,
        DST: opts.dsts.H1_G1,
        expand: opts.expand_fn,
    })
    return bn254.G1.ProjectivePoint.fromAffine(hasher.hashToCurve(identity).toAffine())
}

// Concrete instantiation of H_2 that outputs a uniformly random byte string of length n
// H_2: G_T \rightarrow \{0, 1\}^\ell
export function hashToBytes(shared_key: GT, n: number, opts: IbeOpts): Uint8Array {
    // encode shared_key as BE(shared_key.c0.c0.c0) || BE(shared_key.c0.c0.c1) || BE(shared_key.c0.c1.c0) || ...
    if (opts.expand_fn == "xmd") {
        return expand_message_xmd(bn254.fields.Fp12.toBytes(shared_key), opts.dsts.H2, n, opts.hash)
    } else {
        return expand_message_xof(bn254.fields.Fp12.toBytes(shared_key), opts.dsts.H2, n, opts.k, opts.hash)
    }
}

// Concrete instantiation of H_3 that outputs a point in Fp
// H_3: \{0, 1\}^\ell \times \{0, 1\}^\ell \rightarrow Fp
function hashSigmaMToField(sigma: Uint8Array, m: Uint8Array, opts: IbeOpts): bigint {
    // input = \sigma || m
    const input = new Uint8Array(sigma.length + m.length)
    input.set(sigma)
    input.set(m, sigma.length)

    // hash_to_field(\sigma || m)
    return hash_to_field(input, 1, {
        p: htfDefaultsG1.p,
        m: htfDefaultsG1.m,
        hash: opts.hash,
        k: opts.k,
        DST: opts.dsts.H3,
        expand: opts.expand_fn,
    })[0][0];
}

// Concrete instantiation of H_4 that outputs a uniformly random byte string of length n
// H_4: \{0, 1\}^\ell \rightarrow \{0, 1\}^\ell
function hashSigmaToBytes(sigma: Uint8Array, n: number, opts: IbeOpts): Uint8Array {
    if (opts.expand_fn == "xmd") {
        return expand_message_xmd(sigma, opts.dsts.H4, n, opts.hash)
    } else {
        return expand_message_xof(sigma, opts.dsts.H4, n, opts.k, opts.hash)
    }
}
