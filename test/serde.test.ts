import {describe, it, expect} from "@jest/globals"
import {bn254} from "@kevincharm/noble-bn254-drand"
import {equalBytes} from "@noble/curves/abstract/utils"

import {createIdentity, DEFAULT_OPTS, encrypt} from "../src/crypto"
import {deserializeCiphertext, serializeCiphertext} from "../src/serde"

describe("serde", () => {
    it("ciphertext is the same before and after serialisation", () => {
        const identity = createIdentity(Buffer.from("goodbye"), DEFAULT_OPTS)
        const ciphertext = encrypt(Buffer.from("hello world"), identity, bn254.G2.ProjectivePoint.fromHex("07e1d1d335df83fa98462005690372c643340060d205306a9aa8106b6bd0b3820557ec32c2ad488e4d4f6008f89a346f18492092ccc0d594610de2732c8b808f0095685ae3a85ba243747b1b2f426049010f6b73a0cf1d389351d5aaaa1047f6297d3a4f9749b33eb2d904c9d9ebf17224150ddd7abd7567a9bec6c74480ee0b"), DEFAULT_OPTS)
        const ciphertext2 = deserializeCiphertext(serializeCiphertext(ciphertext))

        expect(ciphertext.U.x).toEqual(ciphertext2.U.x)
        expect(ciphertext.U.y).toEqual(ciphertext2.U.y)
        expect(ciphertext.U.z).toEqual(ciphertext2.U.z)
        expect(ciphertext.U.t).toEqual(ciphertext2.U.t)
        expect(equalBytes(ciphertext.V, ciphertext2.V)).toBeTruthy()
        expect(equalBytes(ciphertext.W, ciphertext2.W)).toBeTruthy()
    })
})
