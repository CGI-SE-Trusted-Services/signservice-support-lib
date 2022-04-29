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

    public final static String DEFAULT_VALIDATION_POLICY_NAME = "/validationpolicy.xml";
    public final static String DEFAULT_VALIDATION_TRUSTSTORE_TYPE = "JKS";
    public final static String DEFAULT_VALIDATION_STRICT = "false";
    public final static String DEFAULT_VALIDATION_DISABLE_REVOCATIONCHECK = "false";

    public final static Integer DEFAULT_TRANSACTION_TTL = 660;

    public final static String DEFAULT_IMAGE_PATH = "/visibleSignatures/CGI_Logon.png";
    public final static String VISIBLE_SIGNATURE_REQUEST_TIME = "visible_signature_request_time";
}
