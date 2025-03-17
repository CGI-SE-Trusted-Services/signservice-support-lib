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

import org.signatureservice.messages.MessageProcessingException;
import se.signatureservice.configuration.common.InvalidArgumentException;

/**
 * Class listing all available sign algorithms and based on the
 * reference code provided by elegitimationsnamnden.
 *
 * @author Philip Vendil
 *
 */
public enum SignAlgorithm {
    RSA_SHA1,
    RSA_SHA256,
    RSA_SHA512,
    RSA_SSA_PSS_SHA512_MGF1,
    ECDSA_SHA256;

    public static final String ALG_URI_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    public static final String ALG_URI_RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    public static final String ALG_URI_RSA_SSA_PSS_SHA512_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1";
    public static final String ALG_URI_ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    public static final String ALG_URI_RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    public static final String ALG_JAVA_RSA_SHA256 = "SHA256withRSA";
    public static final String ALG_JAVA_RSA_SHA512 = "SHA512withRSA";
    public static final String ALG_JAVA_RSA_SSA_PSS_SHA512_MGF1 = "SHA512withRSAandMGF1";
    public static final String ALG_JAVA_ECDSA_SHA256 = "SHA256withECDSA";
    public static final String ALG_JAVA_RSA_SHA1 = "SHA1withRSA";

    public static final String HASH_ALG_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
    public static final String HASH_ALG_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    public static final String HASH_ALG_SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";

    static {
        RSA_SHA1.digestAlgo = HASH_ALG_SHA1;
        RSA_SHA1.sigAlgo = ALG_URI_RSA_SHA1;
        RSA_SHA1.messageDigestName = "SHA-1";
        RSA_SHA1.digestAlgOid = "1.3.14.3.2.26";
        RSA_SHA1.signAlgOid = "1.2.840.113549.1.1.5";

        RSA_SHA256.digestAlgo = HASH_ALG_SHA256;
        RSA_SHA256.sigAlgo = ALG_URI_RSA_SHA256;
        RSA_SHA256.messageDigestName = "SHA-256";
        RSA_SHA256.digestAlgOid = "2.16.840.1.101.3.4.2.1";
        RSA_SHA256.signAlgOid = "1.2.840.113549.1.1.11";

        RSA_SHA512.digestAlgo = HASH_ALG_SHA512;
        RSA_SHA512.sigAlgo = ALG_URI_RSA_SHA512;
        RSA_SHA512.messageDigestName = "SHA-512";
        RSA_SHA512.digestAlgOid = "2.16.840.1.101.3.4.2.3";
        RSA_SHA512.signAlgOid = "1.2.840.113549.1.1.11";

        RSA_SSA_PSS_SHA512_MGF1.digestAlgo = HASH_ALG_SHA512;
        RSA_SSA_PSS_SHA512_MGF1.sigAlgo = ALG_URI_RSA_SSA_PSS_SHA512_MGF1;
        RSA_SSA_PSS_SHA512_MGF1.messageDigestName = "SHA-512";
        RSA_SSA_PSS_SHA512_MGF1.digestAlgOid = "2.16.840.1.101.3.4.2.3";
        RSA_SSA_PSS_SHA512_MGF1.signAlgOid = "1.2.840.113549.1.1.10";

        ECDSA_SHA256.digestAlgo = HASH_ALG_SHA256;
        ECDSA_SHA256.sigAlgo = ALG_URI_ECDSA_SHA256;
        ECDSA_SHA256.messageDigestName = "SHA-256";
        ECDSA_SHA256.digestAlgOid = "2.16.840.1.101.3.4.2.1";
        ECDSA_SHA256.signAlgOid = "1.2.840.10045.4.3.2";

    }

    private static int[] sha256Prefix = new int[]{0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    private String digestAlgo;
    private String sigAlgo;
    private String messageDigestName;
    private String digestAlgOid;
    private String signAlgOid;

    public String getDigestAlgo() {
        return digestAlgo;
    }

    String getSigAlgo() {
        return sigAlgo;
    }

    public String getMessageDigestName() {
        return messageDigestName;
    }

    String getDigestAlgOid() {
        return digestAlgOid;
    }

    String getSignAlgOid() {
        return signAlgOid;
    }

    static SignAlgorithm getAlgoByURI(String algoURI) throws InvalidArgumentException {
        if (algoURI.equalsIgnoreCase(ALG_URI_ECDSA_SHA256)) {
            return ECDSA_SHA256;
        }
        if (algoURI.equalsIgnoreCase(ALG_URI_RSA_SSA_PSS_SHA512_MGF1)) {
            return RSA_SSA_PSS_SHA512_MGF1;
        }
        if (algoURI.equalsIgnoreCase(ALG_URI_RSA_SHA512)) {
            return RSA_SHA512;
        }
        if (algoURI.equalsIgnoreCase(ALG_URI_RSA_SHA256)) {
            return RSA_SHA256;
        }
        if (algoURI.equalsIgnoreCase(ALG_URI_RSA_SHA1)) {
            return RSA_SHA1;
        }
        throw new InvalidArgumentException("Unsupported Signature Algorithm: " + algoURI);
    }

    public static SignAlgorithm getAlgoByJavaName(String algoName) throws MessageProcessingException {
        if (algoName.equalsIgnoreCase(ALG_JAVA_ECDSA_SHA256)) {
            return ECDSA_SHA256;
        }
        if (algoName.equalsIgnoreCase(ALG_JAVA_RSA_SSA_PSS_SHA512_MGF1)) {
            return RSA_SSA_PSS_SHA512_MGF1;
        }
        if (algoName.equalsIgnoreCase(ALG_JAVA_RSA_SHA512)) {
            return RSA_SHA512;
        }
        if (algoName.equalsIgnoreCase(ALG_JAVA_RSA_SHA256)) {
            return RSA_SHA256;
        }
        if (algoName.equalsIgnoreCase(ALG_JAVA_RSA_SHA1)) {
            return RSA_SHA1;
        }
        throw new MessageProcessingException("Unsupported Signature Algorithm: " + algoName);
    }
}
