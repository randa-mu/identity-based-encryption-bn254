import {describe, it, expect} from "@jest/globals"
import {keccak_256} from "@noble/hashes/sha3"
import {bn254} from "@kevincharm/noble-bn254-drand"
import {IBE} from "../src"
import {hashIdentityToG1, hashToBytes, IbeOpts} from "../src/crypto"

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

    it("decryption key can be verified", () => {
        const i_m = Buffer.from("blah")
        const identity = ibe.createIdentity(i_m)

        const decryptionKey = ibe.createDecryptionKey(secretKey, identity)

        expect(ibe.isValidDecryptionKey(publicKey, decryptionKey, i_m)).toBeTruthy()
    })
})

describe("ibe bn254 KATs", () => {
    it("h1", async () => {
        const OPTS: IbeOpts = {
            hash: keccak_256,
            k: 128,
            expand_fn: "xmd",
            dsts: {
                H1_G1: Buffer.from("TEST_IBE_BN254G1_XMD:KECCAK-256_SVDW_RO_H1_"),
                H2: Buffer.from("TEST_IBE_BN254_XMD:KECCAK-256_H2_"),
                H3: Buffer.from("TEST_IBE_BN254_XMD:KECCAK-256_H3_"),
                H4: Buffer.from("TEST_IBE_BN254_XMD:KECCAK-256_H4_"),
            }
        }

        let g1 = hashIdentityToG1(Buffer.from(""), OPTS)
        expect(g1.x).toEqual(BigInt("3653173467790182248506061396572709101962704209335577284294737943301013580835"))
        expect(g1.y).toEqual(BigInt("2746942348379889347830045590181038295853386711647916449093173473614869629216"))

        g1 = hashIdentityToG1(Buffer.from("AAAA"), OPTS)
        expect(g1.x).toEqual(BigInt("16321686657743529192052651493099263906314638256513471437877788171012494023490"))
        expect(g1.y).toEqual(BigInt("1350849970859344403057974536687145189475558284863891842544885697009576643682"))

        g1 = hashIdentityToG1(Buffer.from("UOOQHNXMOVXWJZYTFTJCVYZCIXBSPVQY"), OPTS)
        expect(g1.x).toEqual(BigInt("8929120621272588982321893216115445711479984949242622726428064156435284450717"))
        expect(g1.y).toEqual(BigInt("14990022920127397634122290672777445403200199610320581106924212874052592382108"))
    })

    it("h2", async () => {
        const OPTS: IbeOpts = {
            hash: keccak_256,
            k: 128,
            expand_fn: "xmd",
            dsts: {
                H1_G1: Buffer.from("TEST_IBE_ G1_XMD:KECCAK-256_SVDW_RO_H1_"),
                H2: Buffer.from("TEST_IBE_BN254_XMD:KECCAK-256_H2_"),
                H3: Buffer.from("TEST_IBE_BN254_XMD:KECCAK-256_H3_"),
                H4: Buffer.from("TEST_IBE_BN254_XMD:KECCAK-256_H4_"),
            }
        }

        let gt = bn254.pairing(bn254.G1.ProjectivePoint.BASE, bn254.G2.ProjectivePoint.BASE)
        let h2 = hashToBytes(gt, 32, OPTS)
        expect(Buffer.from(h2)).toEqual(Buffer.from("ad886214af94515c0d08269799f69ef80ccd8f6f63ccc40bfcd6517c5b62510c", "hex"))

        gt = bn254.pairing(bn254.G1.ProjectivePoint.BASE.double(), bn254.G2.ProjectivePoint.BASE)
        h2 = hashToBytes(gt, 32, OPTS)
        expect(Buffer.from(h2)).toEqual(Buffer.from("80a06d11d632a76edf7c3b2772f8c4d9d72095295315977620d224b363c3c49c", "hex"))

        gt = bn254.pairing(bn254.G1.ProjectivePoint.BASE.double(), bn254.G2.ProjectivePoint.BASE.double())
        h2 = hashToBytes(gt, 32, OPTS)
        expect(Buffer.from(h2)).toEqual(Buffer.from("39dc28417110a63f330a0dca9ff58bb936cfcb70407c875f5a114a56488112f5", "hex"))
    })
})
