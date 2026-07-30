import SwiftASN1

enum ValidationError: Error {
    case incorrectSerialization
    case roundTripMismatch
    case malformedPEMAccepted
}

@main
struct SwiftASN1WASMValidation {
    static func main() throws {
        try validateCanonicalSerialization()
        try validateAllByteValuesRoundTrip()
        try validateMalformedInputRejection()
        print("swift-asn1 WASM validation passed")
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
