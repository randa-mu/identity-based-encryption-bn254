import {bn254} from "@kevincharm/noble-bn254-drand"
import {Fp} from "@noble/curves/abstract/tower"
import {ProjPointType} from "@noble/curves/abstract/weierstrass"
import {Ciphertext, createIdentity, decrypt, DEFAULT_OPTS, encrypt, G2, IbeOpts} from "./crypto"

export class IBE {
    constructor(private opts: IbeOpts = DEFAULT_OPTS) {
    }

    createIdentity(bytes: Uint8Array): Identity {
        return {
            i: createIdentity(bytes, this.opts),
            m: bytes
        }
    }

    createDecryptionKey(secretKey: SecretKey | Uint8Array, identity: Identity): DecryptionKey {
        const sk = secretKey instanceof Uint8Array ? bn254.fields.Fr.fromBytes(secretKey) : secretKey.sk
        return {bytes: bn254.ShortSignature.toRawBytes(identity.i.multiply(sk))}
    }

    isValidDecryptionKey(publicKey: PublicKey | Uint8Array, decryptionKey: DecryptionKey | Uint8Array, identity: Identity | Uint8Array): boolean {
        const sig = decryptionKey instanceof Uint8Array ? decryptionKey : decryptionKey.bytes
        const pk = publicKey instanceof Uint8Array ? IBE.parsePublicKey(publicKey) : publicKey
        const m = identity instanceof Uint8Array ? identity : identity.m
        return bn254.verifyShortSignature(sig, m, bn254.G2.ProjectivePoint.fromAffine(pk.p), {DST: this.opts.dsts.H1_G1})
    }

    encrypt(message: Uint8Array, identity: Identity, publicKey: PublicKey) {
        return encrypt(message, identity.i, publicKey.p, this.opts)
    }

    decrypt(ciphertext: Ciphertext, decryptionKey: DecryptionKey | Uint8Array): Uint8Array {
        try {
            const key = decryptionKey instanceof Uint8Array ? decryptionKey : decryptionKey.bytes
            return decrypt(ciphertext, bn254.G1.ProjectivePoint.fromHex(key).toAffine(), this.opts)
        } catch (err) {
            throw new Error("failed to decrypt the ciphertext - did you use the correct key?")
        }
    }

    static parsePublicKey(bytes: Uint8Array): PublicKey {
        return {p: bn254.G2.ProjectivePoint.fromHex(bytes).toAffine()}
    }

    static parseDecryptionKey(bytes: Uint8Array): DecryptionKey {
        return {bytes: bytes}
    }

    static parseSecretKey(sk: Uint8Array | bigint): SecretKey {
        return {sk: sk instanceof Uint8Array ? bn254.fields.Fr.fromBytes(sk) : sk}
    }

    static createSecretKey(): SecretKey {
        return {sk: bn254.fields.Fr.fromBytes(bn254.utils.randomPrivateKey())}
    }

    static createPublicKey(secretKey: SecretKey): PublicKey {
        return {p: bn254.G2.ProjectivePoint.BASE.multiply(secretKey.sk).toAffine()}
    }

}

export type SecretKey = {
    sk: bigint
}

export type Identity = {
    m: Uint8Array
    i: ProjPointType<Fp>
}

export type PublicKey = {
    p: G2
}

export type DecryptionKey = {
    bytes: Uint8Array
}
