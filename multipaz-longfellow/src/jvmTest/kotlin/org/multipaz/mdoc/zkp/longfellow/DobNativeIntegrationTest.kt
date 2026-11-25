package org.multipaz.mdoc.zkp.longfellow

import kotlinx.io.bytestring.ByteString
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class DobNativeIntegrationTest {

    private val circuitId =
        "b603047bcc80a2cc2d4e7932852a60b41134ae87dfe10290655c4d6591c88926"

    private fun dobAttribute(date: String): NativeAttribute {
        val encodedDate = byteArrayOf(
            0xd9.toByte(),
            0x03,
            0xec.toByte(),
            0x6a
        ) + date.encodeToByteArray()

        return NativeAttribute(
            key = "birth_date",
            namespace = "org.iso.18013.5.1",
            value = encodedDate
        )
    }

    @Test
    fun dobProofThroughKotlinJna() {
        val home = Path.of(System.getProperty("user.home"))

        val nativeLibrary = home.resolve(
            "multipaz-dob/multipaz-longfellow/rust/target/debug/libzkp.so"
        )

        assertTrue(Files.isRegularFile(nativeLibrary))

        System.setProperty(
            "multipaz.longfellow.nativeLibraryPath",
            nativeLibrary.toAbsolutePath().toString()
        )

        val fixture = Path.of("/tmp/longfellow-dob-cli-test")

        val metadata = Files.readAllLines(
            fixture.resolve("metadata.txt")
        )
        assertEquals(4, metadata.size)

        val pkx = metadata[0]
        val pky = metadata[1]
        val docType = metadata[2]
        val now = metadata[3]

        val circuit = ByteString(
            Files.readAllBytes(
                home.resolve("longfellow-dob-only-export/circuits.zst")
            )
        )

        val mdoc = ByteString(
            Files.readAllBytes(fixture.resolve("mdoc.bin"))
        )

        val transcript = ByteString(
            Files.readAllBytes(fixture.resolve("transcript.bin"))
        )

        val existingProof = ByteString(
            Files.readAllBytes(fixture.resolve("proof.bin"))
        )

        val spec = LongfellowZkSystemSpec(
            system = "longfellow-libzk-v1",
            circuitHash = circuitId,
            numAttributes = 1L,
            version = 8L,
            blockEncHash = 5264L,
            blockEncSig = 4445L
        )

        val cutoff = "1960-01-01"
        val earliest = "1980-12-31"

        // Never give the verifier the real DOB.
        val verifierAttributes = arrayOf(
            dobAttribute("1999-01-01")
        )

        println("1. Verify existing DOB proof through Kotlin/JNA")

        val existingResult = LongfellowNatives.runMdocVerifierDob(
            circuit = circuit,
            circuitSize = circuit.size,
            pkx = pkx,
            pky = pky,
            transcript = transcript,
            transcriptSize = transcript.size,
            now = now,
            proof = existingProof,
            proofSize = existingProof.size,
            docType = docType,
            zkSpec = spec,
            statements = verifierAttributes,
            cutoff = cutoff,
            earliest = earliest
        )

        assertEquals(0, existingResult)

        println("2. Generate a new DOB proof through Kotlin/JNA")

        val newProof = LongfellowNatives.runMdocProverDob(
            circuit = circuit,
            circuitSize = circuit.size,
            mdoc = mdoc,
            mdocSize = mdoc.size,
            pkx = pkx,
            pky = pky,
            transcript = transcript,
            transcriptSize = transcript.size,
            now = now,
            docType = docType,
            zkSpec = spec,
            statements = listOf(dobAttribute("1971-09-01")),
            cutoff = cutoff,
            earliest = earliest
        )

        assertTrue(newProof.isNotEmpty())
        println("Kotlin-generated proof size: ${newProof.size} bytes")

        println("3. Verify Kotlin-generated proof")

        val result = LongfellowNatives.runMdocVerifierDob(
            circuit = circuit,
            circuitSize = circuit.size,
            pkx = pkx,
            pky = pky,
            transcript = transcript,
            transcriptSize = transcript.size,
            now = now,
            proof = ByteString(newProof),
            proofSize = newProof.size,
            docType = docType,
            zkSpec = spec,
            statements = verifierAttributes,
            cutoff = cutoff,
            earliest = earliest
        )

        assertEquals(0, result)

        println("4. Reject incorrect public DOB bounds")

        val badBoundsResult = LongfellowNatives.runMdocVerifierDob(
            circuit = circuit,
            circuitSize = circuit.size,
            pkx = pkx,
            pky = pky,
            transcript = transcript,
            transcriptSize = transcript.size,
            now = now,
            proof = ByteString(newProof),
            proofSize = newProof.size,
            docType = docType,
            zkSpec = spec,
            statements = verifierAttributes,
            cutoff = "2000-01-01",
            earliest = "2010-12-31"
        )

        assertNotEquals(0, badBoundsResult)

        println("5. Reject incorrect circuit ID")

        val badSpecResult = LongfellowNatives.runMdocVerifierDob(
            circuit = circuit,
            circuitSize = circuit.size,
            pkx = pkx,
            pky = pky,
            transcript = transcript,
            transcriptSize = transcript.size,
            now = now,
            proof = ByteString(newProof),
            proofSize = newProof.size,
            docType = docType,
            zkSpec = spec.copy(circuitHash = "0".repeat(64)),
            statements = verifierAttributes,
            cutoff = cutoff,
            earliest = earliest
        )

        assertNotEquals(0, badSpecResult)

        println("ALL KOTLIN DOB NATIVE TESTS PASSED")
    }
}
