package org.multipaz.mdoc.zkp.longfellow

import org.multipaz.verification.MdocVerifiedPresentation
import org.multipaz.verification.VerificationUtil
import org.multipaz.mdoc.zkp.ZkSystemRepository
import org.multipaz.mdoc.response.buildDeviceResponse
import org.multipaz.mdoc.response.DeviceResponse
import org.multipaz.mdoc.request.buildDeviceRequest
import org.multipaz.mdoc.request.ZkRequest
import org.multipaz.mdoc.request.UseCase
import org.multipaz.mdoc.request.DocumentSet
import org.multipaz.mdoc.request.DocRequestInfo
import org.multipaz.mdoc.request.DeviceRequestInfo
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.coroutines.test.runTest
import kotlinx.io.bytestring.ByteString
import org.multipaz.cbor.Cbor
import org.multipaz.mdoc.response.MdocDocument
import org.multipaz.mdoc.zkp.ProofVerificationFailureException
import org.multipaz.mdoc.zkp.ZkDocument
import org.multipaz.mdoc.zkp.ZkSystemSpec
import org.multipaz.request.MdocRequestedClaim
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

class DobApplicationIntegrationTest {

    @Test
    fun completeDobPresentation() = runTest(timeout = 5.minutes) {
        val home = Path.of(System.getProperty("user.home"))
        val fixture = Path.of("/tmp/longfellow-dob-cli-test")

        val library = home.resolve(
            "multipaz-dob/multipaz-longfellow/rust/target/debug/libzkp.so"
        )
        assertTrue(Files.isRegularFile(library))

        System.setProperty(
            "multipaz.longfellow.nativeLibraryPath",
            library.toAbsolutePath().toString()
        )

        val metadata = Files.readAllLines(fixture.resolve("metadata.txt"))
        assertEquals(4, metadata.size)

        val timestamp = Instant.parse(metadata[3])

        // Google's fixture is a complete DeviceResponse, not a bare mDL.
        val response = Cbor.decode(
            Files.readAllBytes(fixture.resolve("mdoc.bin"))
        )

        val documents = response["documents"].asArray
        assertTrue(documents.isNotEmpty())

        val document = MdocDocument.fromDataItem(documents.first())

        println("Document type: ${document.docType}")
        println("Device authentication present: ${document.deviceAuth != null}")

        assertEquals("org.iso.18013.5.1.mDL", document.docType)

        val dobItem = assertNotNull(
            document.issuerNamespaces.data["org.iso.18013.5.1"]
                ?.get("birth_date")
        )
        println("Authenticated DOB element found: ${dobItem != null}")

        // We deliberately retain the key-binding requirement.
        assertNotNull(
            document.deviceAuth,
            "Google fixture has no deviceAuth; a compatible " +
                "key-bound fixture is needed for this application API"
        )

        val transcript = Cbor.decode(
            Files.readAllBytes(fixture.resolve("transcript.bin"))
        )

        val circuit = ByteString(
            Files.readAllBytes(
                home.resolve("longfellow-dob-only-export/circuits.zst")
            )
        )

        val system = LongfellowZkSystem()

        assertTrue(system.addDobCircuit(circuit))

        val spec = system.systemSpecs.single()

        val cutoff = "1960-01-01"
        val earliest = "1980-12-31"

        println("1. Generating application-level DOB proof")

        val proofDocument = system.generateDobProof(
            zkSystemSpec = spec,
            document = document,
            sessionTranscript = transcript,
            timestamp = timestamp,
            cutoff = cutoff,
            earliest = earliest
        )

        println("Proof size: ${proofDocument.proof.size} bytes")

        // The complete issuer-signed credential remains private.
        assertTrue(proofDocument.documentData.issuerSigned.isEmpty())
        assertTrue(proofDocument.documentData.deviceSigned.isEmpty())

        println("2. Serializing and parsing ZkDocument")

        val serialized = Cbor.encode(proofDocument.toDataItem())
        val parsed = ZkDocument.fromDataItem(Cbor.decode(serialized))

        assertTrue(parsed.documentData.issuerSigned.isEmpty())
        assertTrue(parsed.documentData.deviceSigned.isEmpty())
        assertEquals(spec.id, parsed.documentData.zkSystemSpecId)

        // Additional regression guard for accidental plaintext inclusion.
        assertFalse(
            serialized.decodeToString().contains("1971-09-01"),
            "The serialized presentation contains the actual DOB"
        )

        println("3. Verifying the parsed presentation")

        system.verifyDobProof(
            zkDocument = parsed,
            zkSystemSpec = spec,
            sessionTranscript = transcript,
            atTime = timestamp,
            maxTimestampDrift = 5.minutes,
            cutoff = cutoff,
            earliest = earliest
        )

        println("4. Rejecting incorrect DOB bounds")

        assertFailsWith<ProofVerificationFailureException> {
            system.verifyDobProof(
                zkDocument = parsed,
                zkSystemSpec = spec,
                sessionTranscript = transcript,
                atTime = timestamp,
                maxTimestampDrift = 5.minutes,
                cutoff = "2000-01-01",
                earliest = "2010-12-31"
            )
        }

        println("5. Rejecting a modified session transcript")

        val invalidTranscript = Cbor.decode(
            byteArrayOf(0x80.toByte())
        )

        assertFailsWith<ProofVerificationFailureException> {
            system.verifyDobProof(
                zkDocument = parsed,
                zkSystemSpec = spec,
                sessionTranscript = invalidTranscript,
                atTime = timestamp,
                maxTimestampDrift = 5.minutes,
                cutoff = cutoff,
                earliest = earliest
            )
        }


        println("6. Matching an explicit DOB interval request")

        val requestedSpec = ZkSystemSpec(
            id = "dob-interval-request-test",
            system = system.name
        ).apply {
            addParam(
                "circuit_hash",
                "b603047bcc80a2cc2d4e7932852a60b41134ae87dfe10290655c4d6591c88926"
            )
            addParam("num_attributes", 1)
            addParam("version", 8)
            addParam("block_enc_hash", 5264)
            addParam("block_enc_sig", 4445)
            addParam("dob_cutoff", cutoff)
            addParam("dob_earliest", earliest)
        }

        val birthDateClaim = MdocRequestedClaim(
            docType = "org.iso.18013.5.1.mDL",
            namespaceName = "org.iso.18013.5.1",
            dataElementName = "birth_date",
            intentToRetain = false
        )

        val matchedSpec = assertNotNull(
            system.getMatchingSystemSpec(
                zkSystemSpecs = listOf(requestedSpec),
                requestedClaims = listOf(birthDateClaim)
            ),
            "DOB request did not match the registered circuit"
        )

        assertEquals(requestedSpec.id, matchedSpec.id)
        assertEquals(cutoff, matchedSpec.getParam<String>("dob_cutoff"))
        assertEquals(earliest, matchedSpec.getParam<String>("dob_earliest"))

        println("7. Generating proof through generic ZkSystem API")

        val dispatchedProof = system.generateProof(
            zkSystemSpec = matchedSpec,
            document = document,
            sessionTranscript = transcript,
            timestamp = timestamp
        )

        assertTrue(dispatchedProof.documentData.issuerSigned.isEmpty())
        assertTrue(dispatchedProof.documentData.deviceSigned.isEmpty())

        val dispatchedEncoded = Cbor.encode(dispatchedProof.toDataItem())
        assertFalse(dispatchedEncoded.decodeToString().contains("1971-09-01"))

        val dispatchedParsed = ZkDocument.fromDataItem(
            Cbor.decode(dispatchedEncoded)
        )

        println("8. Verifying through generic ZkSystem API")

        system.verifyProof(
            zkDocument = dispatchedParsed,
            zkSystemSpec = matchedSpec,
            sessionTranscript = transcript,
            atTime = timestamp,
            maxTimestampDrift = 5.minutes
        )

        println("9. Checking generic verification rejects incorrect bounds")

        val wrongBoundsSpec = ZkSystemSpec(
            id = matchedSpec.id,
            system = system.name
        ).apply {
            for ((key, value) in matchedSpec.params) {
                addParam(key, value.toDataItem())
            }
            addParam("dob_cutoff", "2000-01-01")
            addParam("dob_earliest", "2010-12-31")
        }

        assertFailsWith<ProofVerificationFailureException> {
            system.verifyProof(
                zkDocument = dispatchedParsed,
                zkSystemSpec = wrongBoundsSpec,
                sessionTranscript = transcript,
                atTime = timestamp,
                maxTimestampDrift = 5.minutes
            )
        }


        println("10. Testing DeviceRequest and DeviceResponse")

        val repository = ZkSystemRepository().add(system)

        val deviceRequest = buildDeviceRequest(
            sessionTranscript = transcript,
            deviceRequestInfo = DeviceRequestInfo.fromValues(
                useCases = listOf(
                    UseCase(
                        mandatory = true,
                        documentSets = listOf(DocumentSet(listOf(0))),
                        purposeHints = emptyMap()
                    )
                )
            )
        ) {
            addDocRequest(
                docType = "org.iso.18013.5.1.mDL",
                nameSpaces = mapOf(
                    "org.iso.18013.5.1" to mapOf(
                        "birth_date" to false
                    )
                ),
                docRequestInfo = DocRequestInfo(
                    zkRequest = ZkRequest(
                        systemSpecs = listOf(requestedSpec),
                        zkRequired = true
                    )
                )
            )
        }

        val deviceResponse = buildDeviceResponse(
            sessionTranscript = transcript,
            status = DeviceResponse.STATUS_OK
        ) {
            addZkDocument(
                dispatchedParsed.copy(docRequestIds = listOf(0))
            )
        }

        println("11. Verifying through VerificationUtil")

        val verifiedPresentations =
            VerificationUtil.verifyMdocDeviceResponse(
                now = timestamp,
                deviceResponse = deviceResponse.toDataItem(),
                sessionTranscript = transcript,
                eReaderKey = null,
                documentTypeRepository = null,
                zkSystemRepository = repository,
                request = deviceRequest
            )

        assertEquals(1, verifiedPresentations.size)

        val presentation =
            verifiedPresentations.single() as MdocVerifiedPresentation

        assertTrue(presentation.zkpUsed)
        assertEquals(requestedSpec.id, presentation.zkSystemSpecId)

        // No date of birth or other personal attributes disclosed.
        assertTrue(presentation.issuerSignedClaims.isEmpty())
        assertTrue(presentation.deviceSignedClaims.isEmpty())

        // The verifier receives only the proven public interval.
        assertEquals(1, presentation.verifiedDobPredicates.size)

        val verifiedPredicate =
            presentation.verifiedDobPredicates.single()

        assertEquals(cutoff, verifiedPredicate.lowerBound)
        assertEquals(earliest, verifiedPredicate.upperBound)

        println("DEVICE REQUEST/RESPONSE DOB VERIFICATION PASSED")

        println("12. Rejecting a DOB proof without a request")

        assertFailsWith<Exception> {
            VerificationUtil.verifyMdocDeviceResponse(
                now = timestamp,
                deviceResponse = deviceResponse.toDataItem(),
                sessionTranscript = transcript,
                eReaderKey = null,
                documentTypeRepository = null,
                zkSystemRepository = repository,
                request = null
            )
        }

        fun makeTestRequest(
            spec: ZkSystemSpec,
            element: String
        ) = buildDeviceRequest(
            sessionTranscript = transcript,
            deviceRequestInfo = DeviceRequestInfo.fromValues(
                useCases = listOf(
                    UseCase(
                        mandatory = true,
                        documentSets = listOf(DocumentSet(listOf(0))),
                        purposeHints = emptyMap()
                    )
                )
            )
        ) {
            addDocRequest(
                docType = "org.iso.18013.5.1.mDL",
                nameSpaces = mapOf(
                    "org.iso.18013.5.1" to mapOf(element to false)
                ),
                docRequestInfo = DocRequestInfo(
                    zkRequest = ZkRequest(
                        systemSpecs = listOf(spec),
                        zkRequired = true
                    )
                )
            )
        }

        println("13. Rejecting different DOB interval bounds")

        val changedBoundsSpec = ZkSystemSpec(
            id = requestedSpec.id,
            system = requestedSpec.system
        ).apply {
            for ((key, value) in requestedSpec.params) {
                addParam(key, value.toDataItem())
            }
            addParam("dob_cutoff", "2000-01-01")
            addParam("dob_earliest", "2010-12-31")
        }

        assertFailsWith<Exception> {
            VerificationUtil.verifyMdocDeviceResponse(
                now = timestamp,
                deviceResponse = deviceResponse.toDataItem(),
                sessionTranscript = transcript,
                eReaderKey = null,
                documentTypeRepository = null,
                zkSystemRepository = repository,
                request = makeTestRequest(changedBoundsSpec, "birth_date")
            )
        }

        println("14. Rejecting an unrelated attribute request")

        assertFailsWith<Exception> {
            VerificationUtil.verifyMdocDeviceResponse(
                now = timestamp,
                deviceResponse = deviceResponse.toDataItem(),
                sessionTranscript = transcript,
                eReaderKey = null,
                documentTypeRepository = null,
                zkSystemRepository = repository,
                request = makeTestRequest(requestedSpec, "family_name")
            )
        }

        println("ALL DEVICE REQUEST SECURITY TESTS PASSED")


        println("ALL APPLICATION AND DISPATCH DOB TESTS PASSED")
    }
}
