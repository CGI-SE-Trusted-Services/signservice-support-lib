/************************************************************************
 *                                                                       *
 *  Signature Service - Support Service Library                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3 of the License, or any later version.                      *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.support.common.keygen;

import se.signatureservice.messages.MessageProcessingException;
import se.signatureservice.configuration.common.InvalidArgumentException;

/**
 * Enum listing supported signature algorithms.
 * Each entry holds its digest algorithm, signature URI, digest name, and OIDs.
 *
 * Based on reference code from E-legitimationsnämnden.
 *
 * @author Philip Vendil
 */
public enum SignAlgorithm {
    RSA_SHA256,
    RSA_SHA384,
    RSA_SHA512,
    RSA_SSA_PSS_SHA512_MGF1,
    ECDSA_SHA256,
    ECDSA_SHA384,
    ECDSA_SHA512;

    // --- Signature Algorithm URIs ---
    public static final String ALG_URI_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    public static final String ALG_URI_RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    public static final String ALG_URI_RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    public static final String ALG_URI_RSA_SSA_PSS_SHA512_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1";
    public static final String ALG_URI_ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    public static final String ALG_URI_ECDSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    public static final String ALG_URI_ECDSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";

    // --- Java Security Names ---
    public static final String ALG_JAVA_RSA_SHA256 = "SHA256withRSA";
    public static final String ALG_JAVA_RSA_SHA384 = "SHA384withRSA";
    public static final String ALG_JAVA_RSA_SHA512 = "SHA512withRSA";
    public static final String ALG_JAVA_RSA_SSA_PSS_SHA512_MGF1 = "SHA512withRSAandMGF1";
    public static final String ALG_JAVA_ECDSA_SHA256 = "SHA256withECDSA";
    public static final String ALG_JAVA_ECDSA_SHA384 = "SHA384withECDSA";
    public static final String ALG_JAVA_ECDSA_SHA512 = "SHA512withECDSA";

    // --- Digest Algorithm URIs ---
    public static final String HASH_ALG_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    public static final String HASH_ALG_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    public static final String HASH_ALG_SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";

    private String digestAlgoUri;
    private String sigAlgoUri;
    private String messageDigestName;
    private String digestAlgOid;
    private String signAlgOid;

    static {
        // --- RSA ---
        RSA_SHA256.init(HASH_ALG_SHA256, ALG_URI_RSA_SHA256, "SHA-256",
                "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.11");

        RSA_SHA384.init(HASH_ALG_SHA384, ALG_URI_RSA_SHA384, "SHA-384",
                "2.16.840.1.101.3.4.2.2", "1.2.840.113549.1.1.12");

        RSA_SHA512.init(HASH_ALG_SHA512, ALG_URI_RSA_SHA512, "SHA-512",
                "2.16.840.1.101.3.4.2.3", "1.2.840.113549.1.1.13");

        RSA_SSA_PSS_SHA512_MGF1.init(HASH_ALG_SHA512, ALG_URI_RSA_SSA_PSS_SHA512_MGF1, "SHA-512",
                "2.16.840.1.101.3.4.2.3", "1.2.840.113549.1.1.10");

        // --- ECDSA ---
        ECDSA_SHA256.init(HASH_ALG_SHA256, ALG_URI_ECDSA_SHA256, "SHA-256",
                "2.16.840.1.101.3.4.2.1", "1.2.840.10045.4.3.2");

        ECDSA_SHA384.init(HASH_ALG_SHA384, ALG_URI_ECDSA_SHA384, "SHA-384",
                "2.16.840.1.101.3.4.2.2", "1.2.840.10045.4.3.3");

        ECDSA_SHA512.init(HASH_ALG_SHA512, ALG_URI_ECDSA_SHA512, "SHA-512",
                "2.16.840.1.101.3.4.2.3", "1.2.840.10045.4.3.4");
    }

    private void init(String digestAlgoUri, String sigAlgoUri, String messageDigestName,
                      String digestAlgOid, String signAlgOid) {
        this.digestAlgoUri = digestAlgoUri;
        this.sigAlgoUri = sigAlgoUri;
        this.messageDigestName = messageDigestName;
        this.digestAlgOid = digestAlgOid;
        this.signAlgOid = signAlgOid;
    }

    public String getDigestAlgoUri() {
        return digestAlgoUri;
    }

    public String getSigAlgoUri() {
        return sigAlgoUri;
    }

    public String getMessageDigestName() {
        return messageDigestName;
    }

    public String getDigestAlgOid() {
        return digestAlgOid;
    }

    public String getSignAlgOid() {
        return signAlgOid;
    }

    public static SignAlgorithm getAlgoByURI(String algoURI) throws InvalidArgumentException {
        for (SignAlgorithm alg : values()) {
            if (alg.getSigAlgoUri().equalsIgnoreCase(algoURI)) {
                return alg;
            }
        }
        throw new InvalidArgumentException("Unsupported Signature Algorithm URI: " + algoURI);
    }

    public static SignAlgorithm getAlgoByJavaName(String algoName) throws MessageProcessingException {
        switch (algoName) {
            case ALG_JAVA_RSA_SHA256: return RSA_SHA256;
            case ALG_JAVA_RSA_SHA384: return RSA_SHA384;
            case ALG_JAVA_RSA_SHA512: return RSA_SHA512;
            case ALG_JAVA_RSA_SSA_PSS_SHA512_MGF1: return RSA_SSA_PSS_SHA512_MGF1;
            case ALG_JAVA_ECDSA_SHA256: return ECDSA_SHA256;
            case ALG_JAVA_ECDSA_SHA384: return ECDSA_SHA384;
            case ALG_JAVA_ECDSA_SHA512: return ECDSA_SHA512;
            default:
                throw new MessageProcessingException("Unsupported Signature Algorithm: " + algoName);
        }
    }
}