import {bn254} from "@kevincharm/noble-bn254-drand"
import {Fp} from "@noble/curves/abstract/tower"
import {ProjPointType} from "@noble/curves/abstract/weierstrass"
import {Ciphertext, createIdentity, decrypt, DEFAULT_OPTS, encrypt, G1, G2, IbeOpts} from "./crypto"

export class IBE {
    constructor(private opts: IbeOpts = DEFAULT_OPTS) {
    }

    createIdentity(bytes: Uint8Array): Identity {
        return {i: createIdentity(bytes, this.opts)}
    }

    createDecryptionKey(secretKey: SecretKey | Uint8Array, identity: Identity): DecryptionKey {
        const sk = secretKey instanceof Uint8Array ? bn254.fields.Fr.fromBytes(secretKey) : secretKey.sk
        return {k: identity.i.multiply(sk).toAffine()}
    }

    encrypt(message: Uint8Array, identity: Identity, publicKey: PublicKey) {
        return encrypt(message, identity.i, publicKey.p, this.opts)
    }

    decrypt(ciphertext: Ciphertext, decryptionKey: DecryptionKey | Uint8Array): Uint8Array {
        try {
            const key = decryptionKey instanceof Uint8Array ? bn254.G1.ProjectivePoint.fromHex(decryptionKey) : decryptionKey.k
            return decrypt(ciphertext, key, this.opts)
        } catch (err) {
            throw new Error("failed to decrypt the ciphertext - did you use the correct key?")
        }
    }

    static parsePublicKey(bytes: Uint8Array): PublicKey {
        return {p: bn254.G2.ProjectivePoint.fromHex(bytes)}
    }

    static parseDecryptionKey(bytes: Uint8Array): DecryptionKey {
        return {k: bn254.G1.ProjectivePoint.fromHex(bytes)}
    }

    static createSecretKey(): SecretKey {
        return {sk: bn254.fields.Fr.fromBytes(bn254.utils.randomPrivateKey())}
    }

    static createPublicKey(secretKey: SecretKey): PublicKey {
        return {p: bn254.G2.ProjectivePoint.BASE.multiply(secretKey.sk)}
    }

}

export type SecretKey = {
    sk: bigint
}

export type Identity = {
    i: ProjPointType<Fp>,
}

export type PublicKey = {
    p: G2
}

export type DecryptionKey = {
    k: G1
}
