import {describe, it, expect} from "@jest/globals"
import {IBE} from "../src"

describe("encryption", () => {
    const ibe = new IBE()
    const secretKey = IBE.createSecretKey()
    const publicKey = IBE.createPublicKey(secretKey)

    it("can be decrypted with the correct identity", () => {
        const message = Buffer.from("hello world")
        const identity = ibe.createIdentity(Buffer.from("blah"))
        const ciphertext = ibe.encrypt(message, identity, publicKey)

        const decryptionKey = ibe.createDecryptionKey(secretKey, identity)
        const plaintext = ibe.decrypt(ciphertext, decryptionKey)

        expect(Buffer.from(plaintext).equals(message)).toBeTruthy()
    })

    it("cannot be decrypted with the wrong identity", () => {
        const message = Buffer.from("hello world")
        const identity = ibe.createIdentity(Buffer.from("blah"))
        const ciphertext = ibe.encrypt(message, identity, publicKey)

        const incorrectDecryptionKey = ibe.createDecryptionKey(secretKey, ibe.createIdentity(Buffer.from("banana")))

        expect(() => ibe.decrypt(ciphertext, incorrectDecryptionKey)).toThrowError()
    })
})
