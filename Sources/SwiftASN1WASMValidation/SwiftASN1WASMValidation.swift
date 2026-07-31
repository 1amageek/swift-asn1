import SwiftASN1

enum ValidationError: Error {
    case incorrectSerialization
    case integerSerializationMismatch
    case sequenceParsingMismatch
    case roundTripMismatch
    case malformedPEMAccepted
}

@main
struct SwiftASN1WASMValidation {
    static func main() throws {
        try validateIntegerSerialization()
        try validateDERAndBERSequences()
        try validateCanonicalSerialization()
        try validateAllByteValuesRoundTrip()
        try validateMalformedInputRejection()
        print("swift-asn1 WASM validation passed")
    }

    private static func validateIntegerSerialization() throws {
        let signedFixtures: [(value: Int, bytes: [UInt8])] = [
            (0, [0x02, 0x01, 0x00]),
            (127, [0x02, 0x01, 0x7f]),
            (128, [0x02, 0x02, 0x00, 0x80]),
            (-1, [0x02, 0x01, 0xff]),
            (-129, [0x02, 0x02, 0xff, 0x7f]),
        ]
        for fixture in signedFixtures {
            var serializer = DER.Serializer()
            try serializer.serialize(fixture.value)
            guard serializer.serializedBytes == fixture.bytes else {
                throw ValidationError.integerSerializationMismatch
            }
            guard try Int(derEncoded: serializer.serializedBytes) == fixture.value else {
                throw ValidationError.integerSerializationMismatch
            }
        }

        var unsignedSerializer = DER.Serializer()
        try unsignedSerializer.serialize(UInt(128))
        guard unsignedSerializer.serializedBytes == [0x02, 0x02, 0x00, 0x80] else {
            throw ValidationError.integerSerializationMismatch
        }
    }

    private static func validateDERAndBERSequences() throws {
        let derBytes: [UInt8] = [
            0x30, 0x06,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x02,
        ]
        let derValues = try DER.sequence(
            of: Int.self,
            identifier: .sequence,
            rootNode: DER.parse(derBytes)
        )
        guard derValues == [1, 2] else {
            throw ValidationError.sequenceParsingMismatch
        }

        let berBytes: [UInt8] = [
            0x30, 0x80,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x02,
            0x00, 0x00,
        ]
        let berValues = try BER.sequence(
            of: Int.self,
            identifier: .sequence,
            rootNode: BER.parse(berBytes)
        )
        guard berValues == [1, 2] else {
            throw ValidationError.sequenceParsingMismatch
        }

        let setBytes: [UInt8] = [
            0x31, 0x06,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x02,
        ]
        let lazyValues = try DER.lazySet(
            of: Int.self,
            identifier: .set,
            rootNode: DER.parse(setBytes)
        )
        var parsedValues: [Int] = []
        for value in lazyValues {
            parsedValues.append(try value.get())
        }
        guard parsedValues == [1, 2] else {
            throw ValidationError.sequenceParsingMismatch
        }
    }

    private static func validateCanonicalSerialization() throws {
        let document = PEMDocument(type: "DATA", derBytes: [0x4d, 0x61])
        let expected = """
            -----BEGIN DATA-----
            TWE=
            -----END DATA-----
            """
        guard document.pemString == expected else {
            throw ValidationError.incorrectSerialization
        }
    }

    private static func validateAllByteValuesRoundTrip() throws {
        let bytes = (UInt16(0)...UInt16(255)).map { UInt8($0) }
        let serialized = PEMDocument(type: "DATA", derBytes: bytes).pemString
        let parsed = try PEMDocument(pemString: serialized)
        guard parsed.discriminator == "DATA", parsed.derBytes == bytes else {
            throw ValidationError.roundTripMismatch
        }
    }

    private static func validateMalformedInputRejection() throws {
        let malformed = """
            -----BEGIN DATA-----
            AQ%=
            -----END DATA-----
            """
        do {
            _ = try PEMDocument(pemString: malformed)
            throw ValidationError.malformedPEMAccepted
        } catch let error as ASN1Error {
            guard error.code == .invalidPEMDocument else {
                throw error
            }
        }
    }
}
