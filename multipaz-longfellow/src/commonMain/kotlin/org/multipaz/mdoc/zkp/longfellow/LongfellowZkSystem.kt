package org.multipaz.mdoc.zkp.longfellow

import org.multipaz.request.MdocRequestedClaim
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.format
import kotlinx.datetime.toLocalDateTime
import kotlinx.io.bytestring.ByteString
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.buildCborMap
import org.multipaz.crypto.EcPublicKeyDoubleCoordinate
import org.multipaz.util.Logger
import org.multipaz.mdoc.zkp.ProofVerificationFailureException
import org.multipaz.mdoc.zkp.ZkDocument
import org.multipaz.mdoc.zkp.ZkDocumentData
import org.multipaz.mdoc.zkp.ZkSystem
import org.multipaz.mdoc.zkp.ZkSystemSpec
import kotlin.time.Duration
import kotlin.time.Instant
import org.multipaz.cbor.putCborArray
import org.multipaz.mdoc.response.DeviceResponse
import org.multipaz.mdoc.response.MdocDocument
import org.multipaz.request.RequestedClaim
import org.multipaz.util.toHex
import org.multipaz.util.truncateToWholeSeconds
import kotlin.collections.component1
import kotlin.collections.component2
import kotlin.collections.iterator

private data class CircuitEntry (
    val zkSystemSpec: ZkSystemSpec,
    val longfellowZkSystemSpec: LongfellowZkSystemSpec,
    val circuitBytes: ByteString,
)

/**
 * Abstract base class for Longfellow-based ZK systems implementing [ZkSystem].
 *
 * Provides core logic for proof generation and verification using native Longfellow
 * libraries. Circuit files are expected to be name with the format:
 * `<version>_<numAttributes>_<circuitHash>`.
 */
class LongfellowZkSystem(): ZkSystem {
    private val circuits: MutableList<CircuitEntry> = mutableListOf()

    override val systemSpecs: List<ZkSystemSpec>
        get() = this.circuits.map { it.zkSystemSpec }

    companion object {
        private const val TAG = "LongfellowZkSystem"
        private const val DOB_CIRCUIT_HASH =
            "b603047bcc80a2cc2d4e7932852a60b41134ae87dfe10290655c4d6591c88926"

        // Matches the numeric error code in the native prover's message
        private val errorCodeRegex = Regex("""\d+""")
    }

    override val name: String
        get() = "longfellow-libzk-v1"

    private fun getFormattedCoordinate(value: ByteArray): String {
        return "0x" + value.toHex()
    }

    private fun formatDate(timestamp: Instant): String {
        return timestamp.truncateToWholeSeconds().toLocalDateTime(TimeZone.UTC).format(LocalDateTime.Formats.ISO) + "Z"
    }

    private fun findCircuitEntry(zkSystemSpec: ZkSystemSpec): CircuitEntry? {
        val reqHash = zkSystemSpec.getParam<String>("circuit_hash") ?: return null
        val reqVersion = zkSystemSpec.getParam<Long>("version")
        val reqNumAttributes = zkSystemSpec.getParam<Long>("num_attributes")
        val reqBlockEncHash = zkSystemSpec.getParam<Long>("block_enc_hash")
        val reqBlockEncSig = zkSystemSpec.getParam<Long>("block_enc_sig")
        return circuits
            .filter { circuitEntry ->
                val circuitSpec = circuitEntry.zkSystemSpec
                circuitSpec.getParam<String>("circuit_hash") == reqHash &&
                    (reqVersion == null || circuitSpec.getParam<Long>("version") == reqVersion) &&
                    (reqNumAttributes == null || circuitSpec.getParam<Long>("num_attributes") == reqNumAttributes) &&
                    (reqBlockEncHash == null || circuitSpec.getParam<Long>("block_enc_hash") == reqBlockEncHash) &&
                    (reqBlockEncSig == null || circuitSpec.getParam<Long>("block_enc_sig") == reqBlockEncSig)
            }
            .maxByOrNull { it.zkSystemSpec.getParam<Long>("version") ?: Long.MIN_VALUE }
    }

    private fun getLongfellowZkSystemSpec(zkSystemSpec: ZkSystemSpec): LongfellowZkSystemSpec? =
        findCircuitEntry(zkSystemSpec)?.longfellowZkSystemSpec

    private fun getCircuitBytes(zkSystemSpec: ZkSystemSpec): ByteString? =
        findCircuitEntry(zkSystemSpec)?.circuitBytes

    private fun parseCircuitFilename(circuitFileName: String): Pair<ZkSystemSpec, LongfellowZkSystemSpec>? {
        val circuitNameParts = circuitFileName.split("_")
        if (circuitNameParts.size != 5) {
            Logger.w(TAG, "$circuitFileName does not match expected " +
                "<version>_<numAttributes>_<blockEncHash>_<blockEncSig>_<hash>")
            return null
        }

        val version = circuitNameParts[0].toLongOrNull()
        if (version == null) {
            Logger.w(TAG, "$circuitFileName does not match expected format, could not find version number.")
            return null
        }

        val numAttributes = circuitNameParts[1].toLongOrNull()
        if (numAttributes == null) {
            Logger.w(TAG, "$circuitFileName does not match expected format, could not find number of attributes.")
            return null
        }

        val blockEncHash = circuitNameParts[2].toLongOrNull()
        if (blockEncHash == null) {
            Logger.w(TAG, "$circuitFileName does not match expected format, could not find blockEncHash.")
            return null
        }

        val blockEncSig = circuitNameParts[3].toLongOrNull()
        if (blockEncSig == null) {
            Logger.w(TAG, "$circuitFileName does not match expected format, could not find blockEncSig.")
            return null
        }

        val circuitHash = circuitNameParts[4]

        val spec = ZkSystemSpec(
            id = "${name}_${circuitFileName}",
            system = name,
        )
        spec.addParam("version", version)
        spec.addParam("circuit_hash", circuitHash)
        spec.addParam("num_attributes", numAttributes)
        spec.addParam("block_enc_hash", blockEncHash)
        spec.addParam("block_enc_sig", blockEncSig)

        val longfellowSpec = LongfellowZkSystemSpec(
            system = name,
            circuitHash = circuitHash,
            numAttributes = numAttributes,
            version = version,
            blockEncHash = blockEncHash,
            blockEncSig = blockEncSig
        )

        return Pair(spec, longfellowSpec)
    }


    private fun isDobRequest(spec: ZkSystemSpec): Boolean =
        spec.getParam<String>("circuit_hash") == DOB_CIRCUIT_HASH

    private fun dobBounds(spec: ZkSystemSpec): Pair<String, String> {
        val cutoff = spec.getParam<String>("dob_cutoff")
            ?: throw IllegalArgumentException("Missing dob_cutoff")
        val earliest = spec.getParam<String>("dob_earliest")
            ?: throw IllegalArgumentException("Missing dob_earliest")

        validateDobInterval(cutoff, earliest)
        return cutoff to earliest
    }

    override fun generateProof(
        zkSystemSpec: ZkSystemSpec,
        document: MdocDocument,
        sessionTranscript: DataItem,
        timestamp: Instant
    ): ZkDocument {
        if (isDobRequest(zkSystemSpec)) {
            val (cutoff, earliest) = dobBounds(zkSystemSpec)
            return generateDobProof(
                zkSystemSpec = zkSystemSpec,
                document = document,
                sessionTranscript = sessionTranscript,
                timestamp = timestamp,
                cutoff = cutoff,
                earliest = earliest
            )
        }

        require(document.deviceAuth != null) {
            "Longfellow ZKP requires a key-bound mdoc with deviceAuth"
        }
        val longfellowZkSystemSpec = getLongfellowZkSystemSpec(zkSystemSpec)
            ?: throw IllegalArgumentException("Circuit not found for system spec: $zkSystemSpec")
        val circuitBytes = getCircuitBytes(zkSystemSpec)
            ?: throw IllegalArgumentException("Circuit not found for system spec: $zkSystemSpec")

        Logger.i(TAG, "Generating proof using $zkSystemSpec")

        // The Longfellow ZKP library expects `DeviceResponse` CBOR, and will grab the 1st document in the array.
        val longfellowDocBytes = Cbor.encode(
            buildCborMap {
                put("version", "1.0")
                putCborArray("documents") {
                    add(document.toDataItem())
                }
                put("status", DeviceResponse.STATUS_OK)
            }
        )
        val docType = document.docType
        val issuerCert = document.issuerCertChain.certificates.first()
        val ecPubKeyCoordinates = issuerCert.ecPublicKey as EcPublicKeyDoubleCoordinate
        val x = getFormattedCoordinate(ecPubKeyCoordinates.x)
        val y = getFormattedCoordinate(ecPubKeyCoordinates.y)

        val attributes = mutableListOf<NativeAttribute>()
        val issuerSigned = mutableMapOf<String, Map<String, DataItem>>()
        document.issuerNamespaces.data.forEach { (namespaceName, issuerSignedItemsMap) ->
            val values = mutableMapOf<String, DataItem>()
            issuerSignedItemsMap.forEach { (dataElementName, issuerSignedItem) ->
                values.put(dataElementName, issuerSignedItem.dataElementValue)
                attributes.add(NativeAttribute(
                    key = dataElementName,
                    namespace = namespaceName,
                    value = Cbor.encode(issuerSignedItem.dataElementValue)
                ))
            }
            issuerSigned.put(namespaceName, values)
        }
        // According to Longfellow-ZK spec, can't have any fractional seconds.
        if (timestamp.nanosecondsOfSecond != 0) {
            Logger.w(TAG, "Dropping non-zero fractional seconds for timestamp $timestamp")
        }
        val adjustedTimestamp = timestamp.truncateToWholeSeconds()
        val encodedSessionTranscript = ByteString(Cbor.encode(sessionTranscript))
        val proof = try {
            LongfellowNatives.runMdocProver(
                circuit = circuitBytes,
                circuitSize = circuitBytes.size,
                mdoc = ByteString(longfellowDocBytes),
                mdocSize = longfellowDocBytes.size,
                pkx = x,
                pky = y,
                transcript = encodedSessionTranscript,
                transcriptSize = encodedSessionTranscript.size,
                now = formatDate(adjustedTimestamp),
                docType = docType,
                zkSpec = longfellowZkSystemSpec,
                statements = attributes
            )
        } catch (e: ProofGenerationException) {
            // The native prover only reports a numeric error code. Decode it to be human-readable
            val code = errorCodeRegex.find(e.message ?: "")?.value?.toIntOrNull()
            val decoded = code?.let { ProverCodeEnum.fromInt(it) }
            if (decoded != null) {
                throw ProofGenerationException("Proof generation failed with $decoded")
            }
            throw e
        }

        val zkDocument = ZkDocument(
            proof = ByteString(proof),
            documentData = ZkDocumentData(
                zkSystemSpecId = zkSystemSpec.id,
                docType = docType,
                timestamp = adjustedTimestamp,
                issuerSigned = issuerSigned,
                deviceSigned = emptyMap(),     // TODO: support deviceSigned in Longfellow
                msoX5chain = document.issuerCertChain,
            )
        )

        return zkDocument
    }

    override fun verifyProof(
        zkDocument: ZkDocument,
        zkSystemSpec: ZkSystemSpec,
        sessionTranscript: DataItem,
        atTime: Instant,
        maxTimestampDrift: Duration,
    ) {
        if (isDobRequest(zkSystemSpec)) {
            val (cutoff, earliest) = dobBounds(zkSystemSpec)
            verifyDobProof(
                zkDocument = zkDocument,
                zkSystemSpec = zkSystemSpec,
                sessionTranscript = sessionTranscript,
                atTime = atTime,
                maxTimestampDrift = maxTimestampDrift,
                cutoff = cutoff,
                earliest = earliest
            )
            return
        }

        if (zkDocument.documentData.msoX5chain == null || zkDocument.documentData.msoX5chain!!.certificates.isEmpty()) {
            throw IllegalArgumentException("zkDocument must contain at least 1 certificate in msoX5chain.")
        }
        if (zkDocument.documentData.deviceSigned.isNotEmpty()) {
            throw ProofVerificationFailureException("Longfellow ZK proofs do not support deviceSigned data elements.")
        }
        if ((atTime - zkDocument.documentData.timestamp).absoluteValue > maxTimestampDrift) {
            throw ProofVerificationFailureException(
                "ZK document timestamp ${zkDocument.documentData.timestamp} is outside allowed drift of $maxTimestampDrift from $atTime"
            )
        }

        Logger.i(TAG, "Verifying proof using $zkSystemSpec")

        val cert = zkDocument.documentData.msoX5chain!!.certificates[0]
        val ecPubKeyCoordinates = cert.ecPublicKey as EcPublicKeyDoubleCoordinate
        val x = getFormattedCoordinate(ecPubKeyCoordinates.x)
        val y = getFormattedCoordinate(ecPubKeyCoordinates.y)

        val longfellowZkSystemSpec = getLongfellowZkSystemSpec(zkSystemSpec)
            ?: throw IllegalArgumentException("Circuit not found for system spec: $zkSystemSpec")
        val circuitBytes = getCircuitBytes(zkSystemSpec)
            ?: throw IllegalArgumentException("Circuit not found for system spec: $zkSystemSpec")

        val attributes = mutableListOf<NativeAttribute>()
        for ((nameSpaceName, dataElements) in zkDocument.documentData.issuerSigned) {
            for ((dataElementName, dataElementValue) in dataElements) {
                attributes.add(NativeAttribute(
                    key = dataElementName,
                    namespace = nameSpaceName,
                    value = Cbor.encode(dataElementValue)
                ))
            }
        }

        val encodedSessionTranscript = ByteString(Cbor.encode(sessionTranscript))
        val verifierResult = LongfellowNatives.runMdocVerifier(
            circuitBytes,
            circuitBytes.size,
            x,
            y,
            encodedSessionTranscript,
            encodedSessionTranscript.size,
            formatDate(zkDocument.documentData.timestamp),
            zkDocument.proof,
            zkDocument.proof.size,
            zkDocument.documentData.docType,
            longfellowZkSystemSpec,
            attributes.toTypedArray()
        )

        Logger.i(TAG, "Verification Code: $verifierResult")

        if (verifierResult != VerifierCodeEnum.MDOC_VERIFIER_SUCCESS.value) {
            val verifierCodeEnum = VerifierCodeEnum.fromInt(verifierResult)
            throw ProofVerificationFailureException("Verification failed with error: $verifierCodeEnum")
        }
    }

    /**
     * Longfellow encodes a version number, the number of attributes, and the circuit
     * hash in the filename with the circuit data so in addition to `circuitBytes`, pass this
     * information in `circuitFilename` encoded in the following way:
     * `<version>_<numAttributes>_<circuitHash>`.
     * circuitFilename should be only the name of the file, and must not include any path separators.
     *
     * @param circuitFilename the name of the circuit file
     * @param circuitBytes the bytes of the circuit file
     * @throws IllegalArgumentException if the circuitFilename is invalid
     */

    private fun validateDobInterval(cutoff: String, earliest: String) {
        val pattern = Regex("""\d{4}-\d{2}-\d{2}""")

        require(pattern.matches(cutoff) && pattern.matches(earliest)) {
            "DOB bounds must use YYYY-MM-DD"
        }

        kotlinx.datetime.LocalDate.parse(cutoff)
        kotlinx.datetime.LocalDate.parse(earliest)

        require(cutoff <= earliest) {
            "cutoff must not be after earliest"
        }
    }

    private fun requireDobCircuit(spec: LongfellowZkSystemSpec) {
        require(
            spec.circuitHash == DOB_CIRCUIT_HASH &&
            spec.version == 8L &&
            spec.numAttributes == 1L &&
            spec.blockEncHash == 5264L &&
            spec.blockEncSig == 4445L
        ) {
            "This operation requires the DOB-only Longfellow circuit"
        }
    }

    /**
     * Registers the previously compiled DOB-only circuit.
     * The circuit bytes must correspond to the pinned circuit ID.
     */
    fun addDobCircuit(circuitBytes: ByteString): Boolean =
        addCircuit(
            "8_1_5264_4445_$DOB_CIRCUIT_HASH",
            circuitBytes
        )

    /**
     * Generates a DOB interval proof.
     *
     * The real DOB is used privately by the prover.
     * No issuer-signed personal attributes are returned in ZkDocumentData.
     */
    fun generateDobProof(
        zkSystemSpec: ZkSystemSpec,
        document: MdocDocument,
        sessionTranscript: DataItem,
        timestamp: Instant,
        cutoff: String,
        earliest: String
    ): ZkDocument {
        validateDobInterval(cutoff, earliest)

        require(document.deviceAuth != null) {
            "DOB proof requires a key-bound mdoc"
        }

        val nativeSpec = getLongfellowZkSystemSpec(zkSystemSpec)
            ?: throw IllegalArgumentException("DOB circuit not registered")

        requireDobCircuit(nativeSpec)

        val circuit = getCircuitBytes(zkSystemSpec)
            ?: throw IllegalArgumentException("DOB circuit bytes not found")

        val dobItem = document.issuerNamespaces.data[
            "org.iso.18013.5.1"
        ]?.get("birth_date")
            ?: throw IllegalArgumentException(
                "Issuer-signed birth_date is missing"
            )

        val encodedDob = Cbor.encode(dobItem.dataElementValue)

        require(
            encodedDob.size == 14 &&
            encodedDob[0] == 0xd9.toByte() &&
            encodedDob[1] == 0x03.toByte() &&
            encodedDob[2] == 0xec.toByte() &&
            encodedDob[3] == 0x6a.toByte()
        ) {
            "DOB must be a CBOR tag 1004 full-date"
        }

        val attributes = listOf(
            NativeAttribute(
                key = "birth_date",
                namespace = "org.iso.18013.5.1",
                value = encodedDob
            )
        )

        val mdocBytes = Cbor.encode(
            buildCborMap {
                put("version", "1.0")
                putCborArray("documents") {
                    add(document.toDataItem())
                }
                put("status", DeviceResponse.STATUS_OK)
            }
        )

        val certChain = document.issuerCertChain
        val issuerCert = certChain.certificates.first()
        val coordinates =
            issuerCert.ecPublicKey as EcPublicKeyDoubleCoordinate

        val transcript = ByteString(Cbor.encode(sessionTranscript))
        val adjustedTimestamp = timestamp.truncateToWholeSeconds()

        val proof = LongfellowNatives.runMdocProverDob(
            circuit = circuit,
            circuitSize = circuit.size,
            mdoc = ByteString(mdocBytes),
            mdocSize = mdocBytes.size,
            pkx = getFormattedCoordinate(coordinates.x),
            pky = getFormattedCoordinate(coordinates.y),
            transcript = transcript,
            transcriptSize = transcript.size,
            now = formatDate(adjustedTimestamp),
            docType = document.docType,
            zkSpec = nativeSpec,
            statements = attributes,
            cutoff = cutoff,
            earliest = earliest
        )

        return ZkDocument(
            proof = ByteString(proof),
            documentData = ZkDocumentData(
                zkSystemSpecId = zkSystemSpec.id,
                docType = document.docType,
                timestamp = adjustedTimestamp,
                issuerSigned = emptyMap(),
                deviceSigned = emptyMap(),
                msoX5chain = certChain
            )
        )
    }

    /**
     * Verifies a DOB interval proof using verifier-controlled bounds.
     *
     * The real DOB is neither required nor available to the verifier.
     *
     * Certificate-chain trust validation is the responsibility of the caller.
     */
    fun verifyDobProof(
        zkDocument: ZkDocument,
        zkSystemSpec: ZkSystemSpec,
        sessionTranscript: DataItem,
        atTime: Instant,
        maxTimestampDrift: Duration,
        cutoff: String,
        earliest: String
    ) {
        validateDobInterval(cutoff, earliest)

        if (zkDocument.documentData.zkSystemSpecId != zkSystemSpec.id) {
            throw ProofVerificationFailureException(
                "ZK system specification ID mismatch"
            )
        }

        if (zkDocument.documentData.issuerSigned.isNotEmpty() ||
            zkDocument.documentData.deviceSigned.isNotEmpty()
        ) {
            throw ProofVerificationFailureException(
                "DOB-only presentation must not disclose attributes"
            )
        }

        if ((atTime - zkDocument.documentData.timestamp).absoluteValue >
            maxTimestampDrift
        ) {
            throw ProofVerificationFailureException(
                "DOB proof timestamp is outside allowed drift"
            )
        }

        val nativeSpec = getLongfellowZkSystemSpec(zkSystemSpec)
            ?: throw IllegalArgumentException("DOB circuit not registered")

        requireDobCircuit(nativeSpec)

        val circuit = getCircuitBytes(zkSystemSpec)
            ?: throw IllegalArgumentException("DOB circuit bytes not found")

        val certChain = zkDocument.documentData.msoX5chain
            ?: throw ProofVerificationFailureException(
                "Issuer certificate chain is missing"
            )

        if (certChain.certificates.isEmpty()) {
            throw ProofVerificationFailureException(
                "Issuer certificate chain is empty"
            )
        }

        val coordinates =
            certChain.certificates.first().ecPublicKey
                as EcPublicKeyDoubleCoordinate

        // This placeholder is not the actual DOB.
        // The DOB circuit verifier uses public date bounds instead.
        val dummyDob = byteArrayOf(
            0xd9.toByte(),
            0x03,
            0xec.toByte(),
            0x6a
        ) + "1999-01-01".encodeToByteArray()

        val verifierAttributes = arrayOf(
            NativeAttribute(
                key = "birth_date",
                namespace = "org.iso.18013.5.1",
                value = dummyDob
            )
        )

        val transcript = ByteString(Cbor.encode(sessionTranscript))

        val result = LongfellowNatives.runMdocVerifierDob(
            circuit = circuit,
            circuitSize = circuit.size,
            pkx = getFormattedCoordinate(coordinates.x),
            pky = getFormattedCoordinate(coordinates.y),
            transcript = transcript,
            transcriptSize = transcript.size,
            now = formatDate(zkDocument.documentData.timestamp),
            proof = zkDocument.proof,
            proofSize = zkDocument.proof.size,
            docType = zkDocument.documentData.docType,
            zkSpec = nativeSpec,
            statements = verifierAttributes,
            cutoff = cutoff,
            earliest = earliest
        )

        if (result != VerifierCodeEnum.MDOC_VERIFIER_SUCCESS.value) {
            throw ProofVerificationFailureException(
                "DOB proof verification failed with code $result"
            )
        }
    }

    fun addCircuit(circuitFilename: String, circuitBytes: ByteString): Boolean {
        require(circuitFilename.indexOf("/") == -1) {
            "circuitFilename must not include any directory separator"
        }

        val spec = parseCircuitFilename(circuitFilename)
        if (spec == null) {
            Logger.w(TAG, "Invalid circuit file name: $circuitFilename")
            return false
        }

        return circuits.add(CircuitEntry(spec.first, spec.second, circuitBytes))
    }

    /**
     * Adds the default circuits recommended by the Longfellow authors.
     */
    fun addDefaultCircuits() {
        payloads.forEach { (circuitName, circuitBytes) ->
            addCircuit(
                circuitFilename = circuitName,
                circuitBytes = ByteString(circuitBytes)
            )
        }
    }

    /**
     * Finds the best matching [ZkSystemSpec] from a given list based on the number of signed attributes.
     *
     * @param zkSystemSpecs the available specs from the request
     * @param requestedClaims the requested claims.
     * @return the best matching [ZkSystemSpec], or null if none are suitable
     */
    override fun getMatchingSystemSpec(
        zkSystemSpecs: List<ZkSystemSpec>,
        requestedClaims: List<RequestedClaim>
    ): ZkSystemSpec? {
        val numAttributesRequested = requestedClaims.size.toLong()
        if (numAttributesRequested == 0L) {
            return null
        }


        // The DOB circuit is selected only for an explicit birth_date
        // request, never as a generic attribute-disclosure circuit.
        for (reqSpec in zkSystemSpecs) {
            if (reqSpec.system != name || !isDobRequest(reqSpec)) continue

            val claim = requestedClaims.singleOrNull()
                as? MdocRequestedClaim ?: continue

            if (claim.docType != "org.iso.18013.5.1.mDL" ||
                claim.namespaceName != "org.iso.18013.5.1" ||
                claim.dataElementName != "birth_date"
            ) continue

            val cutoff = reqSpec.getParam<String>("dob_cutoff")
                ?: continue
            val earliest = reqSpec.getParam<String>("dob_earliest")
                ?: continue

            try {
                validateDobInterval(cutoff, earliest)
            } catch (_: IllegalArgumentException) {
                continue
            }

            val entry = findCircuitEntry(reqSpec) ?: continue
            val nativeSpec = entry.longfellowZkSystemSpec

            if (nativeSpec.circuitHash != DOB_CIRCUIT_HASH ||
                nativeSpec.version != 8L ||
                nativeSpec.numAttributes != 1L ||
                nativeSpec.blockEncHash != 5264L ||
                nativeSpec.blockEncSig != 4445L
            ) continue

            val resolved = ZkSystemSpec(
                id = reqSpec.id,
                system = name
            )

            for ((key, value) in entry.zkSystemSpec.params) {
                resolved.addParam(key, value.toDataItem())
            }

            resolved.addParam("dob_cutoff", cutoff)
            resolved.addParam("dob_earliest", earliest)

            return resolved
        }

        var bestMatch: Pair<ZkSystemSpec, Long>? = null
        for (reqSpec in zkSystemSpecs) {
            if (reqSpec.system != name) continue
            if (isDobRequest(reqSpec)) continue
            val reqCircuitHash = reqSpec.getParam<String>("circuit_hash") ?: continue
            val reqVersion = reqSpec.getParam<Long>("version")
            val reqNumAttributes = reqSpec.getParam<Long>("num_attributes")
            if (reqNumAttributes != null && reqNumAttributes != numAttributesRequested) continue
            val reqBlockEncHash = reqSpec.getParam<Long>("block_enc_hash")
            val reqBlockEncSig = reqSpec.getParam<Long>("block_enc_sig")

            for (entry in circuits) {
                val circuitSpec = entry.zkSystemSpec
                val circuitVersion = circuitSpec.getParam<Long>("version") ?: Long.MIN_VALUE
                if (circuitSpec.getParam<String>("circuit_hash") != reqCircuitHash) continue
                if (circuitSpec.getParam<Long>("num_attributes") != numAttributesRequested) continue
                if (reqVersion != null && circuitVersion != reqVersion) continue
                if (reqBlockEncHash != null && circuitSpec.getParam<Long>("block_enc_hash") != reqBlockEncHash) continue
                if (reqBlockEncSig != null && circuitSpec.getParam<Long>("block_enc_sig") != reqBlockEncSig) continue

                if (bestMatch == null || circuitVersion > bestMatch.second) {
                    val resolved = ZkSystemSpec(id = reqSpec.id, system = name)
                    for ((k, v) in circuitSpec.params) {
                        resolved.addParam(k, v.toDataItem())
                    }
                    bestMatch = resolved to circuitVersion
                }
            }
        }
        return bestMatch?.first
    }
}
