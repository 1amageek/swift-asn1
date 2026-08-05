import SSLCore
import SSLASN1

/// Strict DER parser adapter that preserves SwiftASN1's public node shape for
/// existing certificate consumers while delegating byte-level parsing to the
/// canonical SSLASN1 cursor. It does not expose SSLASN1's scoped views as
/// escaping public values.
enum SSLASN1DERBackend {
    private static let maximumInputByteCount = 16 * 1024 * 1024

    static func parse(_ data: ArraySlice<UInt8>) throws(ASN1MetaError) -> ASN1Node {
        let owned = Array(data)
        guard !owned.isEmpty else {
            throw ASN1Error.truncatedASN1Field()
        }
        guard owned.count <= maximumInputByteCount else {
            throw ASN1Error.invalidASN1Object(reason: "DER input exceeds backend limit")
        }

        let limits: ParsingLimits
        do {
            limits = try ParsingLimits(
                maximumInputBytes: maximumInputByteCount,
                maximumNestingDepth: 50,
                maximumElementCount: max(owned.count, 1),
                maximumExtensionCount: max(owned.count, 1),
                maximumOIDBytes: max(owned.count, 1),
                maximumStringBytes: max(owned.count, 1)
            )
        } catch {
            throw ASN1Error.invalidASN1Object(reason: "Invalid DER backend limits")
        }

        do {
            var budget = try ParsingBudget(limits: limits, inputByteCount: owned.count)
            var nodes = [ASN1.ParserNode]()
            nodes.reserveCapacity(min(owned.count, 64))
            let topLevelCount = try parseElements(
                owned[...],
                baseOffset: 0,
                budget: &budget,
                depth: 1,
                enforceSingleRoot: true,
                into: &nodes
            )
            guard topLevelCount == 1 else {
                throw ASN1Error.invalidASN1Object(reason: "Multiple root nodes")
            }

            var result = ASN1.ParseResult(nodes[...])
            let firstNode = result.nodes.removeFirst()
            let rootNode: ASN1Node
            if firstNode.isConstructed {
                let children = result.nodes.prefix { $0.depth > firstNode.depth }
                result.nodes = result.nodes.dropFirst(children.count)
                rootNode = ASN1Node(
                    identifier: firstNode.identifier,
                    content: .constructed(.init(nodes: children, depth: firstNode.depth)),
                    encodedBytes: firstNode.encodedBytes
                )
            } else {
                rootNode = ASN1Node(
                    identifier: firstNode.identifier,
                    content: .primitive(firstNode.dataBytes!),
                    encodedBytes: firstNode.encodedBytes
                )
            }
            guard result.nodes.isEmpty else {
                throw ASN1Error.invalidASN1Object(reason: "Unreachable DER nodes")
            }
            return rootNode
        } catch let error as ASN1Error {
            throw error
        } catch let error as DERError {
            throw map(error)
        } catch let error as ResourceLimitError {
            throw ASN1Error.invalidASN1Object(reason: "DER resource limit: \(error)")
        } catch {
            // Embedded Swift cannot specialize generic Error interpolation here.
            // The typed parser errors above retain the useful diagnostics; this
            // final boundary reports a stable failure without materializing an
            // existential description.
            throw ASN1Error.invalidASN1Object(reason: "DER backend failure")
        }
    }

    private static func parseElements(
        _ source: ArraySlice<UInt8>,
        baseOffset: Int,
        budget: inout ParsingBudget,
        depth: Int,
        enforceSingleRoot: Bool = false,
        into nodes: inout [ASN1.ParserNode]
    ) throws -> Int {
        var elementCount = 0
        try source.withUnsafeBufferPointer { buffer in
            var cursor = DERCursor(Span(_unsafeElements: buffer), baseOffset: baseOffset)
            while !cursor.isAtEnd {
                let element = try cursor.readElement(using: &budget)
                guard element.tag.number <= UInt(UInt.max >> 1) else {
                    throw ASN1Error.invalidASN1Object(reason: "DER tag number exceeds SwiftASN1 range")
                }
                let relativeOffset = element.encodedOffset - baseOffset
                let encodedStart = source.startIndex + relativeOffset
                let encodedEnd = encodedStart + element.encodedBytes.count
                guard relativeOffset >= 0,
                      encodedStart >= source.startIndex,
                      encodedEnd <= source.endIndex
                else {
                    throw DERError.lengthOverflow(offset: element.encodedOffset)
                }

                let identifier = ASN1Identifier(
                    tagWithNumber: element.tag.number,
                    tagClass: map(element.tag.tagClass)
                )
                let contentStart = encodedStart + element.headerByteCount
                let encodedBytes = source[encodedStart..<encodedEnd]
                let dataBytes = element.tag.isConstructed
                    ? nil
                    : source[contentStart..<encodedEnd]
                nodes.append(
                    ASN1.ParserNode(
                        identifier: identifier,
                        depth: depth,
                        isConstructed: element.tag.isConstructed,
                        encodedBytes: encodedBytes,
                        dataBytes: dataBytes
                    )
                )
                elementCount += 1

                if element.tag.isConstructed {
                    try budget.enterContainer()
                    let childSource = source[contentStart..<encodedEnd]
                    _ = try parseElements(
                        childSource,
                        baseOffset: element.encodedOffset + element.headerByteCount,
                        budget: &budget,
                        depth: depth + 1,
                        enforceSingleRoot: false,
                        into: &nodes
                    )
                    try budget.leaveContainer()
                }
                if enforceSingleRoot {
                    try cursor.requireFullyConsumed()
                    break
                }
            }
        }
        return elementCount
    }

    private static func map(_ tagClass: DERTagClass) -> ASN1Identifier.TagClass {
        switch tagClass {
        case .universal:
            return .universal
        case .application:
            return .application
        case .contextSpecific:
            return .contextSpecific
        case .private:
            return .private
        }
    }

    private static func map(_ error: DERError) -> ASN1Error {
        switch error {
        case .truncated:
            return .truncatedASN1Field()
        case .nonMinimalLength, .lengthByteCountExceeded:
            return .unsupportedFieldLength(reason: "Noncanonical DER length")
        case .indefiniteLength:
            return .unsupportedFieldLength(reason: "Indefinite length is not DER")
        case .trailingData:
            return .invalidASN1Object(reason: "Trailing unparsed data is present")
        case .invalidTag, .nonMinimalTag, .tagNumberOverflow, .lengthOverflow, .resourceLimit:
            return .invalidASN1Object(reason: "Invalid DER element")
        }
    }
}
