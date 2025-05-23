import {describe, it, expect} from "@jest/globals"
import {aggregateGroupSignature, createPrivateKey, createPublicKey, split} from "shamir-secret-sharing-bn254"
import {IBE} from "../src"

describe("IBE", () => {
    it("works with shared keys", () => {
        const sk = createPrivateKey()
        const pk = createPublicKey(sk)
        const shares = split(sk, 3, 2)

        const message = Buffer.from("hello world")

        const ibe = new IBE()
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
})