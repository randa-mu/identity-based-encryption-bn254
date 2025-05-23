import * as asn1js from "asn1js"
import {bn254} from "@kevincharm/noble-bn254-drand"
import {Ciphertext} from "./crypto"

/**
 * Serialize Ciphertext to ASN.1 structure
 * Ciphertext ::= SEQUENCE {
 *    u SEQUENCE {
 *        x SEQUENCE {
 *            c0 INTEGER,
 *            c1 INTEGER
 *        },
 *        y SEQUENCE {
 *            c0 INTEGER,
 *            c1 INTEGER
 *        }
 *    },
 *    v OCTET STRING,
 *    w OCTET STRING
 * }
 */
export function serializeCiphertext(ct: Ciphertext): Uint8Array {
    const sequence = new asn1js.Sequence({
        value: [
            new asn1js.Sequence({
                value: [
                    new asn1js.Sequence({
                        value: [
                            asn1js.Integer.fromBigInt(ct.U.x.c0),
                            asn1js.Integer.fromBigInt(ct.U.x.c1),
                        ]
                    }),
                    new asn1js.Sequence({
                        value: [
                            asn1js.Integer.fromBigInt(ct.U.y.c0),
                            asn1js.Integer.fromBigInt(ct.U.y.c1),
                        ]
                    }),
                ]
            }),
            new asn1js.OctetString({ valueHex: ct.V }),
            new asn1js.OctetString({ valueHex: ct.W }),
        ],
    });

    return new Uint8Array(sequence.toBER())
}

export function deserializeCiphertext(ct: Uint8Array): Ciphertext {
    const schema = new asn1js.Sequence({
        name: "ciphertext",
        value: [
            new asn1js.Sequence({
                name: "U",
                value: [
                    new asn1js.Sequence({
                        name: "x",
                        value: [
                            new asn1js.Integer(),
                            new asn1js.Integer(),
                        ]
                    }),
                    new asn1js.Sequence({
                        name: "y",
                        value: [
                            new asn1js.Integer(),
                            new asn1js.Integer(),
                        ]
                    }),
                ]
            }),
            new asn1js.OctetString({ name: "V" }),
            new asn1js.OctetString({ name: "W" }),
        ],
    });

    // Verify the validity of the schema
    const res = asn1js.verifySchema(ct, schema)
    if (!res.verified) {
        throw new Error("invalid ciphertext")
    }

    const V = new Uint8Array(res.result['V'].valueBlock.valueHex)
    const W = new Uint8Array(res.result['W'].valueBlock.valueHex)

    function bytesToBigInt(bytes: ArrayBuffer) {
        const byteArray = Array.from(new Uint8Array(bytes))
        const hex: string = byteArray.map(e => e.toString(16).padStart(2, '0')).join('')
        return BigInt('0x' + hex)
    }
    const x = bn254.fields.Fp2.create({
        c0: bytesToBigInt(res.result['x'].valueBlock.value[0].valueBlock.valueHex),
        c1: bytesToBigInt(res.result['x'].valueBlock.value[1].valueBlock.valueHex),
    })
    const y = bn254.fields.Fp2.create({
        c0: bytesToBigInt(res.result['y'].valueBlock.value[0].valueBlock.valueHex),
        c1: bytesToBigInt(res.result['y'].valueBlock.value[1].valueBlock.valueHex),
    })
    const U = { x, y }

    return {
        U,
        V,
        W,
    }
}
