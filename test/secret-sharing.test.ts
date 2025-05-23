import {describe, it, expect} from "@jest/globals"
import {
    aggregateGroupSignature,
    createPrivateKey,
    createPublicKey,
    createPublicKeyShare,
    split
} from "shamir-secret-sharing-bn254"
import {IBE} from "../src"

describe("IBE", () => {
    const sk = createPrivateKey()
    const pk = createPublicKey(sk)
    const shares = split(sk, 3, 2)
    const message = Buffer.from("hello world")
    const ibe = new IBE()

    it("works with shared keys", () => {
        const identity = ibe.createIdentity(Buffer.from("me@example.com"))
        const ciphertext = ibe.encrypt(message, identity, IBE.parsePublicKey(pk.pk))
        const partialKeys = shares.map(s => {
            const sig = ibe.createDecryptionKey(IBE.parseSecretKey(s.share), identity)
            return {
                index: s.index,
                signature: sig.bytes
            }
        })

        const decryptionKey = aggregateGroupSignature(partialKeys)
        const plaintext = ibe.decrypt(ciphertext, decryptionKey)
        expect(Buffer.from(plaintext).equals(message)).toBeTruthy()
    })

    it("shared public keys verify", () => {
        const share = shares[0].share
        const sharePk = createPublicKeyShare(shares[0])
        const identity = ibe.createIdentity(Buffer.from("me@example.com"))
        const decryptionKey = ibe.createDecryptionKey({sk: share}, identity)
        expect(ibe.isValidDecryptionKey(IBE.parsePublicKey(sharePk.pk), decryptionKey, identity)).toBeTruthy()
    })
})