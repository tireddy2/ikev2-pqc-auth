---
title: "Signature Authentication in the Internet Key Exchange Version 2 (IKEv2) using PQC"
abbrev: "Signature Authentication in IKEv2 using PQC"
category: std

docname: draft-reddy-ipsecme-ikev2-pqc-auth
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "ipsecme"
keyword:
 - PQC
 - IKEv2
 - Digital Signature
 - ML-DSA
 - SLH-DSA

venue:
  group: "ipsecme"
  type: "Working Group"
  mail: "ipsecme@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/ipsec/"


stand_alone: yes
pi: [toc, sortrefs, symrefs, strict, comments, docmapping]

author:
 -
    fullname: Tirumaleswar Reddy
    organization: Nokia
    city: Bangalore
    region: Karnataka
    country: India
    email: "kondtir@gmail.com"
 -
    fullname: Valery Smyslov
    organization: ELVIS-PLUS
    country: Russian Federation
    email: "svan@elvis.ru"
 -
    fullname: Scott Fluhrer
    organization: Cisco Systems
    email: "sfluhrer@cisco.com"

normative:

informative:
  FIPS204:
     title: "FIPS 204: Module-Lattice-Based Digital Signature Standard"
     target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf 
     date: false
  FIPS205:
     title: "FIPS 205: Stateless Hash-Based Digital Signature Standard"
     target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf 
     date: false
  FIPS180:
     title: "NIST, Secure Hash Standard (SHS), FIPS PUB 180-4, August 2015"
     target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf 
     date: false
  FIPS202:
     title: "NIST, SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions, FIPS PUB 202, August 2015."
     target: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf 
     date: false
  Lyu09:
      title: "V. Lyubashevsky, “Fiat-Shamir With Aborts: Applications to Lattice and Factoring-Based Signatures“, ASIACRYPT 2009"
      target: https://www.iacr.org/archive/asiacrypt2009/59120596/59120596.pdf
      date: false

---

--- abstract

Signature-based authentication methods are utilized in IKEv2 {{?RFC7296}}. The current version of the Internet Key Exchange Version 2 (IKEv2) protocol supports traditional digital signatures.

This document outlines how post-quantum digital signatures, specifically Module-Lattice-Based Digital Signatures (ML-DSA) and Stateless Hash-Based Digital Signatures (SLH-DSA), can be employed as authentication methods within the IKEv2 protocol. It introduces ML-DSA and SLH-DSA capability to IKEv2 without necessitating any alterations to existing IKE operations.

--- middle

# Introduction

The Internet Key Exchange, or IKEv2 {{?RFC7296}}, is a key agreement and security negotiation protocol; it is used for key establishment in IPsec.  In the initial set of exchanges, both parties independently select and use their preferred authentication method, which may even differ between the initiator and the responder. In IKEv2, it occurs in the exchange called IKE_AUTH.  One option for the authentication method is digital signatures using public key cryptography.  Currently, traditional digital signatures are defined for use within IKE_AUTH: RSA signatures, Digital Signature Algorithm (DSA) Digital Signature Standard (DSS) and ECDSA. 

The presence of a Cryptographically Relevant Quantum Computer (CRQC) would render state-of-the-art traditional public-key algorithms obsolete and insecure. This is because the assumptions about the intractability of the mathematical problems these algorithms rely on, which offer confident levels of security today, no longer apply in the presence of a CRQC. Consequently, there is a requirement to update protocols and infrastructure to use post-quantum algorithms. Post-quantum algorithms are public-key algorithms designed to be secure against CRQCs as well as classical computers. The traditional cryptographic primitives that need to be replaced by PQC algorithms are discussed in {{?I-D.ietf-pquip-pqc-engineers}}.

Module-Lattice-Based Digital Signatures (ML-DSA) [FIPS204] and Stateless Hash-Based Digital Signatures (SLH-DSA) [FIPS205] are quantum-resistant digital signature schemes standardized by the US National Institute of Standards and Technology (NIST) PQC project. This document specifies the use of the ML-DSA and SLH-DSA algorithms in IKEv2. 

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses terms defined in {{?I-D.ietf-pquip-pqt-hybrid-terminology}}. For the purposes of this document, it is helpful to be able to divide cryptographic algorithms
into two classes:

"Asymmetric Traditional Cryptographic Algorithm": An asymmetric cryptographic algorithm based on integer factorisation, finite field discrete logarithms or elliptic curve discrete logarithms, elliptic curve discrete logarithms, or related mathematical problems. 

"Post-Quantum Algorithm": An asymmetric cryptographic algorithm that is believed to be secure against attacks using quantum computers as well as classical computers. Post-quantum algorithms can also be called quantum-resistant or quantum-safe algorithms. Examples of quantum-resistant digital signature schemes include ML-DSA and SLH-DSA.


# Specifying ML-DSA within IKEv2 {#ml-dsa}

ML-DSA [FIPS204] is a digital signature algorithm (part of the CRYSTALS suite) based on the hardness lattice problems over module lattices (i.e., the Module Learning with Errors problem (MLWE)). The design of the algorithm is based on the "Fiat-Shamir with Aborts" {{Lyu09}} framework introduced by Lyubashevsky, that leverages rejection sampling to render lattice based FS schemes compact and secure. ML-DSA uses uniform distribution over small integers for computing coefficients in error vectors, which makes the scheme easier to implement.

ML-DSA is instantiated with 3 parameter sets for the security categories 2, 3 and 5. Security properties of ML-DSA are discussed in Section 9 of {{?I-D.ietf-lamps-dilithium-certificates}}. This document specifies the use of the ML-DSA algorithm in IKEv2 at three security levels: ML-DSA-44, ML-DSA-65, and ML-DSA-87. 


# Specifying SLH-DSA within IKEv2 {#slh-dsa}

SLH-DSA [FIPS205] utilizes the concept of stateless hash-based signatures. In contrast to stateful signature algorithms, SLH-DSA eliminates the need for maintaining state information during the signing process. SLH-DSA is designed to sign up to 2^64 messages and it offers three security levels. The parameters for each of the security levels were chosen to provide 128 bits of security, 192 bits of security, and 256 bits of security. This document specifies the use of the SLH-DSA algorithm in IKEv2 at three security levels.
It includes the small (S) or fast (F) versions of the algorithm and allows for the use of either SHA-256 [FIPS180] or SHAKE256 [FIPS202] as the hash function. The small version prioritizes smaller signature sizes, making them suitable for resource-constrained environments IoT devices. Conversely, the fast version prioritizes speed over signature size, minimizing the time required to generate and verify signatures.
On the other hand, ML-DSA outperforms SLH-DSA in both signature generation and validation time, as well as signature size. SLH-DSA, in contrast, offers smaller key sizes but larger signature sizes.

The following combinations are defined in SLH-DSA [FIPS205]:

* SLH-DSA-128S-SHA2
* SLH-DSA-128F-SHA2
* SLH-DSA-192S-SHA2
* SLH-DSA-192F-SHA2
* SLH-DSA-256S-SHA2
* SLH-DSA-256F-SHA2
* SLH-DSA-128S-SHAKE
* SLH-DSA-128F-SHAKE
* SLH-DSA-192S-SHAKE
* SLH-DSA-192F-SHAKE
* SLH-DSA-256S-SHAKE
* SLH-DSA-256F-SHAKE

SLH-DSA does not introduce a new hardness assumption beyond those inherent to the underlying hash functions. It builds upon established foundations in cryptography, making it a reliable and robust digital signature scheme for a post-quantum world. While attacks on lattice-based schemes like ML-DSA can compromise their security, SLH-DSA will remain unaffected by these attacks due to its distinct mathematical foundations. This ensures the continued security of systems and protocols that utilize SLH-DSA for digital signatures.

# Signature Algorithm Use and Hashing in IKEv2 with ML-DSA and SLH-DSA

Both ML-DSA and SLH-DSA offer deterministic and randomized signing options. By default, ML-DSA uses a non-deterministic approach, where the private random seed rho' is derived pseudorandomly from the signer’s private key, the message, and a 256-bit string, rnd, generated by an approved Random Bit Generator (RBG). In the deterministic version, rnd is instead a constant 256-bit string. Similarly, SLH-DSA can be deterministic or randomized, depending on whether opt_rand is set to a fixed value or a random one. When opt_rand is set to a public seed (from the public key), SLH-DSA produces deterministic signatures, meaning signing the same message twice will result in the same signature.

In the context of signature-based authentication in IKEv2, the data used for generating a digital signature is unique for each IKEv2 session, as it includes session-specific information like nonces, cryptographic parameters, and identifiers. Thus, both ML-DSA and SLH-DSA can utilize their deterministic versions when used within IKEv2. In both cases, the 'context' input parameter for the signature generation algorithm is set to an empty string.

IKEv2 can use arbitrary signature algorithms as described in {{!RFC7427}}, where the "Digital Signature" authentication method supersedes previously defined signature authentication methods. The three security levels of ML-DSA are identified via AlgorithmIdentifier ASN.1 objects, as specified in {{I-D.ietf-lamps-dilithium-certificates}}. The different combinations of SLH-DSA are identified via AlgorithmIdentifier ASN.1 objects, as specified in {{I-D.ietf-lamps-cms-sphincs-plus}}. Both ML-DSA and SLH-DSA define two signature modes: pure mode and pre-hash mode, as specified in [FIPS204] and [FIPS205], respectively. This document specifies only the use of pure mode for signature-based authentication in IKEv2, where the content is signed directly along with some domain separation information. In pre-hash mode, a digest of the message is signed instead. Both [FIPS204] and [FIPS205] prefer pure mode over pre-hash mode, and neither {{I-D.ietf-lamps-dilithium-certificates}} nor {{I-D.ietf-lamps-cms-sphincs-plus}} discusses pre-hash mode. The data signed to prove the identity of the initiator and responder (as discussed in Section 2.15 of {{!RFC7427}}) typically fits within the memory constraints of the devices involved in the IKEv2 exchange, consisting of nonces, SPIs, and the initial exchange messages, which are manageable in size.

# Mechanisms for Signaling Supported Key Pair Types

The following mechanisms can be used by peers to signal the types of public/private key pairs they possess:

*  One method to ascertain that the key pair type the initiator wants the responder
   to use is through a Certificate Request payload sent by the
   initiator.  For example, the initiator could indicate in the
   Certificate Request payload that it trusts a certificate authority
   certificate signed by an ML-DSA or SLH-DSA key. This indication implies 
   that the initiator can process ML-DSA or SLH-DSA signatures, which means 
   that the responder can use ML-DSA or SLH-DSA keys when authenticating.
*  Another method is to leverage {{?I-D.ietf-ipsecme-ikev2-auth-announce}} that
   allows peers to announce their supported authentication methods. It improves
   interoperability when IKEv2 partners are configured with multiple
   credentials of different type to authenticate each other. The responder includes 
   a SUPPORTED_AUTH_METHODS notification in the IKE_SA_INIT response message 
   containing the PQC digital signature scheme(s) it supports. The initiator includes 
   the SUPPORTED_AUTH_METHODS notification in either the IKE_AUTH request message or 
   in the IKE_INTERMEDIATE request. This notification lists the PQC digital signature 
   scheme(s) supported by the initiator, ordered by preference.

# Security Considerations

ML-DSA and SLH-DSA are modeled under existentially unforgeable digital signatures with respect to an adaptive chosen message attack (EUF-CMA). 

ML-DSA-44, ML-DSA-65, and ML-DSA-87 are designed to offer security comparable with the SHA-256/SHA3-256, AES-192, and AES-256 respectively. Similarly, SLH-DSA-128{S,F}-{SHA2,SHAKE}, SLH-DSA-192{S,F}-{SHA2,SHAKE}, and SLH-DSA-256{S,F}-{SHA2,SHAKE} are designed to offer security comparable with the AES-128, AES-192, and AES-256 respectively.

The Security Considerations section of {{?I-D.ietf-lamps-dilithium-certificates}} and {{?I-D.ietf-lamps-cms-sphincs-plus}} applies to this specification as well.

# Acknowledgements
{:numbered="false"}

Thanks to Stefaan De Cnodder for the discussion and comments.

