/************************************************************************
 *                                                                       *
 *  Signature Service - Support Service Library                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.support.system;

/**
 * Class containing various constants and default values used
 * by the library.
 *
 * @author Tobias Agerberg
 */
public class Constants {
    public final static String SIGN_SSL_KEYSTORE_PATH = "sign.ssl.keystore.path";
    public final static String SIGN_SSL_KEYSTORE_PASSWORD = "sign.ssl.keystore.password";
    public final static String SIGN_SSL_KEYSTORE_TYPE = "sign.ssl.keystore.type";
    public final static String SIGN_SSL_TRUSTSTORE_PATH = "sign.ssl.truststore.path";
    public final static String SIGN_SSL_TRUSTSTORE_PASSWORD = "sign.ssl.truststore.password";
    public final static String SIGN_SSL_TRUSTSTORE_TYPE = "sign.ssl.truststore.type";
    public final static String SIGN_SSL_ALGORITHM = "sign.ssl.algorithm";

    public final static String VALIDATION_TRUSTSTORE_PATH = "validation.truststore.path";
    public final static String VALIDATION_TRUSTSTORE_PASSWORD = "validation.truststore.password";
    public final static String VALIDATION_TRUSTSTORE_TYPE = "validation.truststore.type";
    public final static String VALIDATION_POLICY_NAME = "validation.policy.name";
    public final static String VALIDATION_STRICT = "validation.strict";
    public final static String VALIDATION_DISABLE_REVOCATIONCHECK = "validation.disable.revocationcheck";

    public final static String SIGNATUREALGORITHM = "signaturealgorithm";

    public final static String XADES_SIGNATURELEVEL = "xades.signaturelevel";
    public final static String XADES_SIGNATUREPACKAGING = "xades.signaturepacking";
    public final static String XADES_SIGNEDINFOCANONICALIZATIONMETHOD = "xades.signedinfocanonicalizationmethod";
    public final static String XADES_SIGNEDPROPERTIESCANONICALIZATIONMETHOD = "xades.signedpropertiescanonicalizationmethod";
    public final static String XADES_XPATHLOCATIONSTRING = "xades.xpathlocationstring";

    public final static String PADES_SIGNATURELEVEL = "pades.signaturelevel";
    public final static String PADES_SIGNATUREPACKING = "pades.signaturepacking";

    public final static String CADES_SIGNATURELEVEL = "cades.signaturelevel";
    public final static String CADES_SIGNATUREPACKING = "cades.signaturepacking";

    public final static String DEFAULT_SIGN_SSL_ALGORITHM = "TLSv1.2";

    public final static String DEFAULT_SIGNATUREALGORITHM = "SHA256withRSA";

    public final static String DEFAULT_XADES_SIGNATURELEVEL = "XAdES-BASELINE-B";
    public final static String DEFAULT_XADES_SIGNATUREPACKAGING = "ENVELOPED";
    public final static String DEFAULT_XADES_SIGNEDINFOCANONICALIZATIONMETHOD = "http://www.w3.org/2001/10/xml-exc-c14n#";
    public final static String DEFAULT_XADES_SIGNEDPROPERTIESCANONICALIZATIONMETHOD = "http://www.w3.org/2001/10/xml-exc-c14n#";
    public final static String DEFAULT_XADES_XPATHLOCATIONSTRING = "node()[not(self::Signature)]";

    public final static String DEFAULT_PADES_SIGNATURELEVEL = "PAdES-BASELINE-B";
    public final static String DEFAULT_PADES_SIGNATUREPACKING = "ENVELOPED";

    public final static String DEFAULT_CADES_SIGNATURELEVEL = "CAdES-BASELINE-B";
    public final static String DEFAULT_CADES_SIGNATUREPACKING = "ENVELOPING";

    public final static String DEFAULT_VALIDATION_POLICY_NAME = "/defaultpolicy.xml";
    public final static String DEFAULT_VALIDATION_TRUSTSTORE_TYPE = "JKS";
    public final static String DEFAULT_VALIDATION_STRICT = "false";
    public final static String DEFAULT_VALIDATION_DISABLE_REVOCATIONCHECK = "false";

    public final static Integer DEFAULT_TRANSACTION_TTL = 660;

    public final static String DEFAULT_IMAGE_PATH = "/visibleSignatures/CGI_Logon.png";
    public final static String VISIBLE_SIGNATURE_REQUEST_TIME = "visible_signature_request_time";

    public final static String DEFAULT_USER_ID_ATTRIBUTE_MAPPING = "urn:oid:1.2.752.29.4.13";
    public final static Integer DEFAULT_REQUEST_VALIDITY_IN_MINUTES = 5;
    public final static Integer DEFAULT_REQUEST_VALIDITY_OVERLAP_IN_MINUTES = 2;

    public final static long DEFAULT_VALIDATION_CACHE_EXPIRATION_TIME = 86400000;

    /**
     * Indicates a value as not set.
     */
    public static long NOT_SET = -1;

    /**
     * Message Security Context used when processing Sign Requests
     */
    public static final String CONTEXT_USAGE_SIGNREQUEST = "SIGNREQUEST";

    /**
     * Message Security Context used when verifying and consuming assertions
     */
    public static final String CONTEXT_USAGE_ASSERTIONCONSUME = "ASSERTIONCONSUME";

    /**
     * Context used for meta data signing
     */
    public static final String CONTEXT_USAGE_METADATA_SIGN = "METADATASIGN";

    /**
     * The name of current application
     */
    public static String APPLICATION_NAME = "eid2dss";

    /**
     * The name of current application
     */
    public static String ROLE_NAME = "EID2DSS_ADMIN";

    /**
     * Constants of used credential sub types for PKC certificates.
     */
    public static String CREDENTIAL_SUBTYPE_PKC_PREFIX = "eid2dss_pkc_";
    /**
     * Constants of used credential sub types for QC certificates
     */
    public static String CREDENTIAL_SUBTYPE_QC_PREFIX = "eid2dss_qc_";
    /**
     * Constants of used credential sub types for QC/SSCD certificates
     */
    public static String CREDENTIAL_SUBTYPE_QCSSCD_PREFIX = "eid2dss_qcsscd_";

    /**
     * Contant indicating the key type part of the credential sub type
     */
    public static String CREDENTIAL_SUBTYPE_RSA1024_POSTFIX = "rsa_1024";

    /**
     * Contant indicating the key type part of the credential sub type
     */
    public static String CREDENTIAL_SUBTYPE_RSA2048_POSTFIX = "rsa_2048";

    /**
     * Contant indicating the key type part of the credential sub type
     */
    public static String CREDENTIAL_SUBTYPE_ECDSAP256_POSTFIX = "ecdsa_p256";

    /**
     * Constants of used to specify the name of the token type used.
     */
    public static String TOKEN_TYPE_EID2DSS = "eid2dsstoken";

    /**
     * Special constant indicating specified department is used for verification, i.e should
     * be signed by special Verification CA.
     */
    public static String VERIFICATION_DEPARTMENT = "VERIFICATION";

    /**
     * Entry in cache where the original signrequest is stored temporarly.
     */
    public static String CACHEENTRY_SIGNREQUEST = "CACHEENTRY_SIGNREQUEST";

    /**
     * Limit on how long a signing time element in a xades object might differ with current time and still be acceptable.
     */
    public static final long XADES_SIGNING_TIME_LIMIT_MS = 900000;

    /**
     * Xades signed properties reference type URI
     */
    public static final String REFERENCE_TYPE_XADES_SIGNEDPROPERTIES = "http://uri.etsi.org/01903#SignedProperties";

    /**
     * RSA SHA-256 URI
     */
    public static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    /**
     * Swedish EID DSS profile
     */
    public static final String SWE_EID_DSS_PROFILE = "http://id.elegnamnden.se/csig/1.1/dss-ext/profile";

    /**
     * Swedish EID DSS SAML attribute definitions
     */
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_SN = "urn:oid:2.5.4.4";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_GIVENNAME = "urn:oid:2.5.4.42";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_DISPLAYNAME = "urn:oid:2.16.840.1.113730.3.1.241";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_GENDER = "urn:oid:1.3.6.1.5.5.7.9.3";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_PERSONALIDENTITYNUMBER = "urn:oid:1.2.752.29.4.13";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_DATEOFBIRTH = "urn:oid:1.3.6.1.5.5.7.9.1";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_STREET = "urn:oid:2.5.4.9";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_POSTOFFICEBOX = "urn:oid:2.5.4.18";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_POSTALCODE = "urn:oid:2.5.4.17";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_L = "urn:oid:2.5.4.7";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_C = "urn:oid:2.5.4.6";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_PLACEOFBIRTH = "urn:oid:1.3.6.1.5.5.7.9.2";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_COUNTRYOFCITIZENSHIP = "urn:oid:1.3.6.1.5.5.7.9.4";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_COUNTRYOFRESIDENCE = "";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_TELEPHONENUMBER = "";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_MOBILE = "";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_MAIL = "";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_O = "";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_OU = "";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_ORGANIZATIONIDENTIFIER = "";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_ORGAFFILIATION = "";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_AFFILIATION = "";
    public static final String SWE_EID_DSS_SAML_ATTRIBUTE_TRANSACTIONIDENTIFIER = "";
}
