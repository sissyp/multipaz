# DOB-Only Zero-Knowledge Proofs for Multipaz

## Overview

Experimental integration of privacy-preserving date-of-birth interval
proofs into OWF Multipaz using a modified Longfellow implementation.

The wallet proves that an issuer-authenticated mDL birth_date falls
within a verifier-specified date interval, without disclosing the
actual date of birth.

## Implementation

- Custom Longfellow DOB interval circuit (version 8).
- Rust native prover and verifier exposed through the Multipaz FFI.
- Kotlin native bindings and LongfellowZkSystem integration.
- DOB-specific circuit selection and public interval parameters.
- Request-bound verification and VerifiedDobPredicate results.
- Standard Multipaz mdocPresentment wallet integration.
- Prevention of plaintext fallback when ZK is mandatory.

Public parameters:
- dob_cutoff: inclusive lower DOB bound.
- dob_earliest: inclusive upper DOB bound.

## Verified functionality

JVM integration tests have passed for:

- Native DOB proof generation and verification.
- Kotlin and Rust integration.
- Proof serialization and generic ZkSystem dispatch.
- DeviceRequest / DeviceResponse verification.
- Incorrect interval, missing request, and unrelated claim rejection.
- Wallet-generated proof from a newly issued test mDL.
- No plaintext DOB in the generated presentation.
- Rejection of required-ZK requests without a compatible ZK system.

## Important files

- multipaz-longfellow/rust/src/lib.rs
- multipaz-longfellow/rust/include/mdoc_zk.h
- multipaz-longfellow/src/commonMain/kotlin/org/multipaz/mdoc/zkp/longfellow/LongfellowZkSystem.kt
- multipaz/src/commonMain/kotlin/org/multipaz/verification/VerificationUtil.kt
- multipaz/src/commonMain/kotlin/org/multipaz/verification/MdocVerifiedPresentation.kt
- multipaz-longfellow/src/jvmTest/

## Circuit

The DOB circuit has specification:

- Version: 8
- Attributes: 1
- Block encoding hash: 5264
- Block encoding signature: 4445
- Circuit hash: b603047bcc80a2cc2d4e7932852a60b41134ae87dfe10290655c4d6591c88926

The circuit binary is stored in multipaz-longfellow/src/commonMain/circuits/.
The current integration tests load the circuit explicitly.

## Limitations and future work

- Android native builds and on-device testing are pending.
- iOS and Web DOB implementations are incomplete.
- OpenID4VP/DCQL predicate integration is incomplete.
- Issuer trust, revocation, policy authorization, and request uniqueness
  require additional security hardening.
- Local Rust dependency paths and test fixture paths require portability work.
- Performance measurements on real devices have not been completed.

## Status

Research prototype. Tested on the JVM with synthetic test credentials.
Not production-ready.
