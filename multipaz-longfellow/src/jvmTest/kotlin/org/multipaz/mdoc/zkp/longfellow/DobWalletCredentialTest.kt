package org.multipaz.mdoc.zkp.longfellow

import kotlin.test.assertEquals
import org.multipaz.verification.VerificationUtil
import org.multipaz.verification.MdocVerifiedPresentation
import org.multipaz.prompt.promptModelSilentConsent
import org.multipaz.presentment.mdocPresentment
import org.multipaz.presentment.SimplePresentmentSource
import org.multipaz.mdoc.zkp.ZkSystemSpec
import org.multipaz.mdoc.zkp.ZkSystemRepository
import org.multipaz.mdoc.request.buildDeviceRequest
import org.multipaz.mdoc.request.ZkRequest
import org.multipaz.mdoc.request.UseCase
import org.multipaz.mdoc.request.DocumentSet
import org.multipaz.mdoc.request.DocRequestInfo
import org.multipaz.mdoc.request.DeviceRequestInfo
import org.multipaz.documenttype.DocumentTypeRepository
import java.nio.file.Path
import java.nio.file.Files
import kotlinx.coroutines.test.runTest
import kotlinx.io.bytestring.ByteString
import org.multipaz.asn1.ASN1Integer
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.RawCbor
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.Tstr
import org.multipaz.cbor.buildCborMap
import org.multipaz.cbor.toDataItem
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseLabel
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.X500Name
import org.multipaz.crypto.X509CertChain
import org.multipaz.document.buildDocumentStore
import org.multipaz.mdoc.credential.KeyBoundMdocCredential
import org.multipaz.mdoc.issuersigned.buildIssuerNamespaces
import org.multipaz.mdoc.mso.MobileSecurityObject
import org.multipaz.mdoc.util.MdocUtil
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.ephemeral.EphemeralStorage
import org.multipaz.util.truncateToWholeSeconds
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

class DobWalletCredentialTest {

    @Test
    fun createCompatibleMdlCredential() = runTest(timeout = 5.minutes) {

        val storage = EphemeralStorage()
        val secureArea = SoftwareSecureArea.create(storage)

        val secureAreaRepository = SecureAreaRepository.Builder()
            .add(secureArea)
            .build()

        val documentStore = buildDocumentStore(
            storage = storage,
            secureAreaRepository = secureAreaRepository
        ) {}

        val document = documentStore.createDocument(
            displayName = "DOB ZK test mDL"
        )

        val docType = "org.iso.18013.5.1.mDL"
        val namespace = "org.iso.18013.5.1"

        val now = Clock.System.now().truncateToWholeSeconds()
        val validFrom = now - 1.days
        val validUntil = now + 365.days

        println("1. Creating issuer keys")

        val iacaPrivateKey = Crypto.createEcPrivateKey(EcCurve.P256)

        val iacaCert = MdocUtil.generateIacaCertificate(
            iacaKey = AsymmetricKey.anonymous(iacaPrivateKey),
            subject = X500Name.fromName("C=US,CN=DOB Test IACA"),
            serial = ASN1Integer.fromRandom(128),
            validFrom = validFrom,
            validUntil = validUntil,
            issuerAltNameUrl = "https://example.org",
            crlUrl = "https://example.org/crl"
        )

        val iacaKey = AsymmetricKey.X509CertifiedExplicit(
            X509CertChain(listOf(iacaCert)),
            iacaPrivateKey
        )

        val dsPrivateKey = Crypto.createEcPrivateKey(EcCurve.P256)

        val dsCert = MdocUtil.generateDsCertificate(
            iacaKey = iacaKey,
            dsKey = dsPrivateKey.publicKey,
            subject = X500Name.fromName("C=US,CN=DOB Test DS"),
            serial = ASN1Integer.fromRandom(128),
            validFrom = validFrom,
            validUntil = validUntil
        )

        val dsKey = AsymmetricKey.X509CertifiedExplicit(
            X509CertChain(listOf(dsCert)),
            dsPrivateKey
        )

        println("2. Creating key-bound mDL credential")

        val credential = KeyBoundMdocCredential.create(
            document = document,
            asReplacementForIdentifier = null,
            domain = "mdoc",
            secureArea = secureArea,
            docType = docType,
            createKeySettings =
                SoftwareCreateKeySettings.Builder().build()
        )

        println("3. Building issuer-signed DOB")

        val issuerNamespaces = buildIssuerNamespaces {
            addNamespace(namespace) {
                addDataElement(
                    "birth_date",
                    Tagged(1004, Tstr("1971-09-01"))
                )
            }
        }

        val mso = MobileSecurityObject(
            version = "1.0",
            docType = docType,
            signedAt = validFrom,
            validFrom = validFrom,
            validUntil = validUntil,
            expectedUpdate = null,
            digestAlgorithm = Algorithm.SHA256,
            valueDigests =
                issuerNamespaces.getValueDigests(Algorithm.SHA256),
            deviceKey = credential.getAttestation().publicKey
        )

        val taggedMso = Cbor.encode(
            Tagged(
                Tagged.ENCODED_CBOR,
                Bstr(Cbor.encode(mso.toDataItem()))
            )
        )

        println("4. Signing issuer authentication")

        val protectedHeaders = mapOf<CoseLabel, DataItem>(
            CoseNumberLabel(Cose.COSE_LABEL_ALG) to
                Algorithm.ES256.coseAlgorithmIdentifier!!.toDataItem()
        )

        val unprotectedHeaders = mapOf<CoseLabel, DataItem>(
            CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN) to
                dsKey.certChain.toDataItem()
        )

        val issuerAuth = Cbor.encode(
            Cose.coseSign1Sign(
                signingKey = dsKey,
                message = taggedMso,
                includeMessageInPayload = true,
                protectedHeaders = protectedHeaders,
                unprotectedHeaders = unprotectedHeaders
            ).toDataItem()
        )

        val certificationData = ByteString(
            Cbor.encode(
                buildCborMap {
                    put("nameSpaces", issuerNamespaces.toDataItem())
                    put("issuerAuth", RawCbor(issuerAuth))
                }
            )
        )

        credential.certify(certificationData)

        document.edit {
            provisioned = true
        }

        println("5. Validating credential")

        val validation = credential.validate(now = now)

        for (error in validation.errors) {
            println("Validation error: ${error.message}")
        }

        assertFalse(validation.hasErrors)
        assertTrue(credential.issuerNamespaces.data[namespace]
            ?.containsKey("birth_date") == true)

        println("MINIMAL DOB WALLET CREDENTIAL PASSED")

        println("6. Registering the DOB circuit")

        val home = Path.of(System.getProperty("user.home"))

        val nativeLibrary = home.resolve(
            "multipaz-dob/multipaz-longfellow/rust/target/debug/libzkp.so"
        )

        assertTrue(Files.isRegularFile(nativeLibrary))

        System.setProperty(
            "multipaz.longfellow.nativeLibraryPath",
            nativeLibrary.toAbsolutePath().toString()
        )

        val circuitFile = home.resolve(
            "longfellow-dob-only-export/circuits.zst"
        )

        assertTrue(Files.isRegularFile(circuitFile))

        val zkSystem = LongfellowZkSystem()

        assertTrue(
            zkSystem.addDobCircuit(
                ByteString(Files.readAllBytes(circuitFile))
            )
        )

        val zkRepository = ZkSystemRepository().add(zkSystem)

        val circuitSpec = zkSystem.systemSpecs.single()

        val cutoff = "1960-01-01"
        val earliest = "1980-12-31"

        val requestSpec = ZkSystemSpec(
            id = circuitSpec.id,
            system = circuitSpec.system
        ).apply {
            for ((key, value) in circuitSpec.params) {
                addParam(key, value.toDataItem())
            }
            addParam("dob_cutoff", cutoff)
            addParam("dob_earliest", earliest)
        }

        println("7. Creating a ZK-enabled wallet source")

        val documentTypes = DocumentTypeRepository()

        val source = SimplePresentmentSource(
            documentStore = documentStore,
            documentTypeRepository = documentTypes,
            zkSystemRepository = zkRepository,
            showConsentPromptFn = ::promptModelSilentConsent,
            preferSignatureToKeyAgreement = true,
            domainsMdocSignature = listOf("mdoc")
        )

        println("8. Creating the verifier's DOB request")

        val transcript = Cbor.decode(
            Files.readAllBytes(
                Path.of("/tmp/longfellow-dob-cli-test/transcript.bin")
            )
        )

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
                docType = docType,
                nameSpaces = mapOf(
                    namespace to mapOf("birth_date" to false)
                ),
                docRequestInfo = DocRequestInfo(
                    zkRequest = ZkRequest(
                        systemSpecs = listOf(requestSpec),
                        zkRequired = true
                    )
                )
            )
        }

        println("9. Generating the proof through mdocPresentment")

        val (walletResponse, _) = mdocPresentment(
            deviceRequest = deviceRequest,
            eReaderKey = null,
            sessionTranscript = transcript,
            source = source,
            keyAgreementPossible = emptyList(),
            requesterAppId = null,
            requesterOrigin = "https://verifier.example.com",
            creationTime = now,
            preselectedDocuments = listOf(document),
            onWaitingForUserInput = {},
            onDocumentsInFocus = {}
        )

        // DeviceResponse requires verification before accessing
        // its parsed documents and ZK documents.
        println("9a. Parsing and verifying the wallet response")
        walletResponse.verify(sessionTranscript = transcript)

        println(
            "Wallet response: " +
                "${walletResponse.zkDocuments.size} ZK documents, " +
                "${walletResponse.documents.size} ordinary documents"
        )

        assertEquals(1, walletResponse.zkDocuments.size)
        assertTrue(walletResponse.documents.isEmpty())

        val zkDocument = walletResponse.zkDocuments.single()

        assertTrue(zkDocument.documentData.issuerSigned.isEmpty())
        assertTrue(zkDocument.documentData.deviceSigned.isEmpty())

        val encodedResponse = Cbor.encode(walletResponse.toDataItem())

        assertFalse(
            encodedResponse.decodeToString().contains("1971-09-01"),
            "Wallet response contains plaintext DOB"
        )

        println("10. Verifying the wallet-generated proof")

        val verified = VerificationUtil.verifyMdocDeviceResponse(
            now = now,
            deviceResponse = walletResponse.toDataItem(),
            sessionTranscript = transcript,
            eReaderKey = null,
            documentTypeRepository = documentTypes,
            zkSystemRepository = zkRepository,
            request = deviceRequest
        )

        assertEquals(1, verified.size)

        val presentation =
            verified.single() as MdocVerifiedPresentation

        assertTrue(presentation.zkpUsed)
        assertTrue(presentation.issuerSignedClaims.isEmpty())
        assertTrue(presentation.deviceSignedClaims.isEmpty())

        assertEquals(1, presentation.verifiedDobPredicates.size)

        val predicate = presentation.verifiedDobPredicates.single()

        assertEquals(cutoff, predicate.lowerBound)
        assertEquals(earliest, predicate.upperBound)


        println("11. Checking ZK-required requests cannot fall back to plaintext")

        val noZkSource = SimplePresentmentSource(
            documentStore = documentStore,
            documentTypeRepository = documentTypes,
            zkSystemRepository = null,
            showConsentPromptFn = ::promptModelSilentConsent,
            preferSignatureToKeyAgreement = true,
            domainsMdocSignature = listOf("mdoc")
        )

        val failure = assertFailsWith<Exception> {
            mdocPresentment(
                deviceRequest = deviceRequest,
                eReaderKey = null,
                sessionTranscript = transcript,
                source = noZkSource,
                keyAgreementPossible = emptyList(),
                requesterAppId = null,
                requesterOrigin = "https://verifier.example.com",
                creationTime = now,
                preselectedDocuments = listOf(document),
                onWaitingForUserInput = {},
                onDocumentsInFocus = {}
            )
        }

        val failureMessages = generateSequence(
            failure as Throwable
        ) { it.cause }.mapNotNull { it.message }.toList()

        println("Rejection reason: ${failureMessages.joinToString(" | ")}")

        assertTrue(
            failureMessages.any {
                it.contains("ZK proof is required") ||
                it.contains("no compatible ZK system for required ZK proof")
            },
            "Wallet rejected the request for an unexpected reason"
        )

        println("ZK-REQUIRED PLAINTEXT FALLBACK TEST PASSED")

        println("WALLET-GENERATED DOB ZK PRESENTATION PASSED")

    }
}
