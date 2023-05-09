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
package se.signatureservice.support.api.v2;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.jaxb.common.SchemaFactoryBuilder;
import eu.europa.esig.dss.jaxb.common.XmlDefinerUtils;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.*;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.http.proxy.ProxyProperties;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.EnumUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.util.encoders.Base64;
import org.certificateservices.messages.ContextMessageSecurityProvider;
import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.authcontsaci1.AuthContSaciMessageParser;
import org.certificateservices.messages.authcontsaci1.jaxb.SAMLAuthContextType;
import org.certificateservices.messages.csmessages.manager.MessageSecurityProviderManager;
import org.certificateservices.messages.dss1.core.jaxb.SignResponse;
import org.certificateservices.messages.saml2.assertion.jaxb.*;
import org.certificateservices.messages.sweeid2.dssextenstions1_1.AdESType;
import org.certificateservices.messages.sweeid2.dssextenstions1_1.SigType;
import org.certificateservices.messages.sweeid2.dssextenstions1_1.SignMessageMimeType;
import org.certificateservices.messages.sweeid2.dssextenstions1_1.SweEID2DSSExtensionsMessageParser;
import org.certificateservices.messages.sweeid2.dssextenstions1_1.jaxb.*;
import org.certificateservices.messages.utils.CertUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.xml.sax.SAXException;
import se.signatureservice.configuration.common.InternalErrorException;
import se.signatureservice.configuration.common.InvalidArgumentException;
import se.signatureservice.configuration.common.cache.CacheProvider;
import se.signatureservice.configuration.common.cache.MetaData;
import se.signatureservice.configuration.common.utils.ColorParser;
import se.signatureservice.configuration.common.utils.ConfigUtils;
import se.signatureservice.configuration.support.system.Constants;
import se.signatureservice.support.api.AvailableSignatureAttributes;
import se.signatureservice.support.api.ErrorCode;
import se.signatureservice.support.api.SupportServiceAPI;
import se.signatureservice.support.pdf.PdfBoxSupportObjectFactory;
import se.signatureservice.support.signer.*;
import se.signatureservice.support.system.SupportAPIConfiguration;
import se.signatureservice.support.system.SupportAPIProfile;
import se.signatureservice.support.system.TransactionState;
import se.signatureservice.support.trustlist.TrustedListsCertificateSourceBuilder;
import se.signatureservice.support.utils.DSSLibraryUtils;
import se.signatureservice.support.utils.SupportLibraryUtils;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBElement;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;

import static se.signatureservice.support.api.AvailableSignatureAttributes.*;

/**
 * Implementation of Support Service API version 2.
 *
 * @author Tobias Agerberg
 */
public class V2SupportServiceAPI implements SupportServiceAPI {
    private static final Logger log = LoggerFactory.getLogger(V2SupportServiceAPI.class);

    private XAdESService xAdESService;
    private PAdESService pAdESService;
    private CAdESService cAdESService;
    private Map<String, TSPSource> onlineTSPSources;
    private CertificateVerifier certificateVerifier;
    private DefaultAIASource aiaSource;
    private CRLSource crlSource;
    private OCSPSource ocspSource;
    private Map<SigType, SignatureAttributePreProcessor> signatureAttributePreProcessors = new HashMap<>();

    private final SupportAPIConfiguration apiConfig;
    private final MessageSource messageSource;
    private final CacheProvider cacheProvider;

    private SweEID2DSSExtensionsMessageParser sweEID2DSSExtensionsMessageParser;
    private AuthContSaciMessageParser authContSaciMessageParser;
    private org.certificateservices.messages.sweeid2.dssextenstions1_1.jaxb.ObjectFactory sweEid2ObjectFactory;
    private org.certificateservices.messages.saml2.assertion.jaxb.ObjectFactory saml2ObjectFactory;
    private DatatypeFactory datatypeFactory;


    /**
     * Create an instance of the support service library.
     *
     * @param apiConfig API configuration.
     */
    private V2SupportServiceAPI(SupportAPIConfiguration apiConfig) throws SupportServiceLibraryException {
        try {
            this.apiConfig = apiConfig;
            this.messageSource = apiConfig.getMessageSource();
            this.cacheProvider = apiConfig.getCacheProvider();

            try {
                datatypeFactory = DatatypeFactory.newInstance();
            } catch (DatatypeConfigurationException e) {
                log.error("Failed to create instance of data type factory", e);
            }

            try {
                Init.init();
                MessageSecurityProviderManager.initMessageSecurityProvider(apiConfig.getMessageSecurityProvider());
                sweEid2ObjectFactory = new org.certificateservices.messages.sweeid2.dssextenstions1_1.jaxb.ObjectFactory();
                saml2ObjectFactory = new org.certificateservices.messages.saml2.assertion.jaxb.ObjectFactory();
                sweEID2DSSExtensionsMessageParser = new SweEID2DSSExtensionsMessageParser();
                authContSaciMessageParser = new AuthContSaciMessageParser();
                sweEID2DSSExtensionsMessageParser.init(apiConfig.getMessageSecurityProvider(), null);
            } catch (MessageProcessingException e) {
                log.error("Failed to initialize message security provider", e);
            }

            xAdESService = new XAdESService(getCertificateVerifier());
            pAdESService = new PAdESService(getCertificateVerifier());
            cAdESService = new CAdESService(getCertificateVerifier());

            onlineTSPSources = new HashMap<>();
        } catch (Exception e) {
            throw new SupportServiceLibraryException("Error while creating Support Service API: " + e.getMessage());
        }
    }

    /**
     * Generate prepared signature response that contains a signature request
     * and related information for given set of documents.
     *
     * @param profileConfig           Profile configuration containing various settings to control how the signature request is generated.
     * @param documents               Documents to generate sign request for.
     * @param transactionId           Transaction ID to use or null to let the library generate one automatically.
     * @param signMessage             Signature message to include in the request or null if no signature message should be used.
     * @param user                    Information about the signatory.
     * @param authenticationServiceId Authentication service (identity provider) to use when signing the document.
     * @param consumerURL             Return URL that the user should be redirected to in the end of the signature flow.
     * @param signatureAttributes     Optional attributes to use.
     * @return SignRequestInfo instance that contains the XML signature request along with the transaction state.
     * @throws ClientErrorException If an error occurred when generating the signature request due to client supplied data.
     * @throws ServerErrorException If an internal error occurred when generating the signature request.
     */
    @Override
    public PreparedSignatureResponse prepareSignature(SupportAPIProfile profileConfig, DocumentRequests documents, String transactionId, String signMessage, User user, String authenticationServiceId, String consumerURL, List<Attribute> signatureAttributes) throws ClientErrorException, ServerErrorException {
        long currentTime, operationStart = System.currentTimeMillis();
        int operationTime;
        PreparedSignatureResponse preparedSignature = null;
        try {
            if (transactionId == null) {
                transactionId = SupportLibraryUtils.generateTransactionId();
            } else {
                validateTransactionId(transactionId);
            }

            if (cacheProvider.getBinary(transactionId) != null) {
                log.error("Transaction ID has already been used (Transaction ID: " + transactionId + ")");
                throw (ClientErrorException) ErrorCode.UNSUPPORTED_TRANSACTION_ID.toException("Transaction ID has already been used", messageSource);
            }

            validateDocuments(documents);
            validateAuthenticationServiceId(authenticationServiceId, profileConfig);
            validateProfile(profileConfig);

            ContextMessageSecurityProvider.Context context = new ContextMessageSecurityProvider.Context(Constants.CONTEXT_USAGE_SIGNREQUEST, profileConfig.getRelatedProfile());
            preparedSignature = new PreparedSignatureResponse();
            preparedSignature.setProfile(profileConfig.getRelatedProfile());
            preparedSignature.setActionURL(profileConfig.getSignServiceRequestURL());
            preparedSignature.setTransactionId(transactionId);
            preparedSignature.setSignRequest(generateSignRequest(context, transactionId, documents, signMessage, user, authenticationServiceId, consumerURL, profileConfig, signatureAttributes));

            // Fetch transaction state that is created and stored together with to-be-signed data (TBS).
            // If no transaction state can be read it indicates a problem with generating TBS.
            TransactionState transactionState = fetchTransactionState(transactionId);
            if (transactionState == null) {
                throw ErrorCode.INTERNAL_ERROR.toException("Failed to generate signature request based on given input documents.");
            }

            transactionState.setProfile(profileConfig.getRelatedProfile());
            transactionState.setTransactionId(transactionId);
            transactionState.setSignMessage(signMessage);
            transactionState.setAuthenticationServiceId(authenticationServiceId);
            transactionState.setUser(user);
            transactionState.setDocuments(documents);
            transactionState.setTransactionStart(operationStart);
            transactionState.setCompleted(false);

            storeTransactionState(preparedSignature.getTransactionId(), transactionState);
        } catch (Exception e) {
            if (e instanceof ServerErrorException) {
                throw (ServerErrorException) e;
            } else if (e instanceof ClientErrorException) {
                throw (ClientErrorException) e;
            } else {
                throw (ServerErrorException) ErrorCode.INTERNAL_ERROR.toException("Failed to generate sign request: " + e.getMessage());
            }
        }

        currentTime = System.currentTimeMillis();
        operationTime = (int) (currentTime - operationStart);
        log.info("Sign request successfully generated (" + operationTime + " ms)");

        return preparedSignature;
    }

    /**
     * Process sign response from central signature service and create a complete signature response.
     *
     * @param profileConfig Profile configuration containing various settings to control how the signature request is generated.
     * @param signResponse  Signature response to process.
     * @param transactionId Transaction ID for signature to process
     * @return CompleteSignatureResponse that contains the signed document(s).
     * @throws ClientErrorException If an error occurred when generating the signature request due to client supplied data.
     * @throws ServerErrorException If an internal error occurred when generating the signature request.
     */
    @Override
    public CompleteSignatureResponse completeSignature(SupportAPIProfile profileConfig, String signResponse, String transactionId) throws ClientErrorException, ServerErrorException {
        long currentTime, operationStart = System.currentTimeMillis();
        int operationTime;
        CompleteSignatureResponse signatureResponse;
        X509Certificate[] signatureCertificateChain;
        TransactionState transactionState;
        try {
            transactionState = fetchTransactionState(transactionId);
            if (transactionState == null) {
                log.error("Could not find any transaction related to transaction ID " + transactionId);
                throw (ClientErrorException) ErrorCode.UNKNOWN_TRANSACTION.toException("Could not find transaction", messageSource);
            }

            if (transactionState.isCompleted()) {
                log.error("Transaction has already been completed (TransactionID: " + transactionId + ")");
                throw (ClientErrorException) ErrorCode.UNSUPPORTED_TRANSACTION_ID.toException("Transaction has already been completed", messageSource);
            }

            ContextMessageSecurityProvider.Context context = new ContextMessageSecurityProvider.Context(Constants.CONTEXT_USAGE_SIGNREQUEST, transactionState.getProfile());
            SignResponse response = (SignResponse) synchronizedParseMessage(context, Base64.decode(signResponse.getBytes(StandardCharsets.UTF_8)), true);

            if (!response.getResult().getResultMajor().contains("Success")) {
                throw (ServerErrorException) ErrorCode.SIGN_RESPONSE_FAILED.toException("Sign response failed with error message: " + response.getResult().getResultMessage().getValue());
            }
            if (!response.getRequestID().equals(transactionId)) {
                throw (ClientErrorException) ErrorCode.UNSUPPORTED_TRANSACTION_ID.toException("Sign response transaction ID does not match the sign request transaction ID.");
            }

            List<SignTaskDataType> signTasks = synchronizedGetSignTasks(response);
            signatureCertificateChain = SignTaskHelper.getSignatureCertificateChain(response).toArray(new X509Certificate[0]);

            // Process list of sign tasks and create signed documents.
            // TODO: Support document handling by reference.
            List<Document> signedDocuments = new ArrayList<>();
            for (SignTaskDataType signTask : signTasks) {
                DocumentSigningRequest relatedDocument = null;
                for (Object object : transactionState.getDocuments().getDocuments()) {
                    if (object instanceof DocumentSigningRequest) {
                        DocumentSigningRequest document = (DocumentSigningRequest) object;
                        if (document.referenceId.equals(signTask.getSignTaskId())) {
                            relatedDocument = document;
                        }
                    }
                }
                if (relatedDocument != null) {
                    signedDocuments.add(signDocument(relatedDocument, signTask, signatureCertificateChain, transactionState, profileConfig));
                }
            }

            signatureResponse = new CompleteSignatureResponse();
            CompleteSignatureResponse.DocumentResponses documentResponses = new CompleteSignatureResponse.DocumentResponses();
            documentResponses.documents = new ArrayList<>();
            documentResponses.documents.addAll(signedDocuments);
            signatureResponse.setDocuments(documentResponses);
        } catch (Exception e) {
            log.error("Error while processing sign response: " + e.getMessage());

            if (e instanceof ServerErrorException) {
                throw (ServerErrorException) e;
            } else if (e instanceof ClientErrorException) {
                throw (ClientErrorException) e;
            } else {
                throw (ServerErrorException) ErrorCode.INTERNAL_ERROR.toException("Failed to process sign response: " + e.getMessage());
            }
        }

        try {
            transactionState.setCompleted(true);
            storeTransactionState(transactionId, transactionState);
        } catch (Exception e) {
            throw (ServerErrorException) ErrorCode.INTERNAL_ERROR.toException("Failed to store transaction state: " + e.getMessage());
        }

        currentTime = System.currentTimeMillis();
        operationTime = (int) (currentTime - operationStart);
        log.info("Sign response successfully processed (" + operationTime + " ms)");

        return signatureResponse;
    }

    /**
     * Verify a signed document.
     *
     * @param profileConfig  Profile configuration containing various settings to control how the document is verified.
     * @param signedDocument Signed document to verify.
     * @return VerifyDocumentResponse that contains the result of the verification.
     * @throws ClientErrorException If an error occurred when verifying the document due to client supplied data.
     * @throws ServerErrorException If an internal error occurred when verifying the document.
     */
    @Override
    public VerifyDocumentResponse verifyDocument(SupportAPIProfile profileConfig, Document signedDocument) throws ClientErrorException, ServerErrorException {
        VerifyDocumentResponse response;
        Reports reports;
        int validSignatures = 0;
        response = new VerifyDocumentResponse();
        response.setReferenceId(signedDocument.referenceId);

        try {
            DSSDocument dssDocument = DSSLibraryUtils.createDSSDocument(signedDocument);
            SignedDocumentValidator validator = null;
            try {
                validator = SignedDocumentValidator.fromDocument(dssDocument);
            } catch (Exception e) {
                log.error("Failed to create signed document validator: " + e.getMessage());
                response.setVerifies(false);
                response.setSignatures(new Signatures());
                return response;
            }

            List<Signature> signatures = new ArrayList<>();
            if (validator != null) {
                if (signedDocument.isHasDetachedSignature()) {
                    List<DSSDocument> detachedContentsList = new ArrayList<>();
                    InMemoryDocument inMemoryDocument = new InMemoryDocument();
                    inMemoryDocument.setBytes(signedDocument.getDetachedSignatureData());
                    detachedContentsList.add(inMemoryDocument);
                    validator.setDetachedContents(detachedContentsList);
                }

                validator.setCertificateVerifier(getCertificateVerifier());

                // Removing unsupported attributes to solve "SECURITY : unable to set attribute(s)" error
                SchemaFactoryBuilder schemaFactoryBuilder = SchemaFactoryBuilder.getSecureSchemaBuilder();
                schemaFactoryBuilder.removeAttribute(XMLConstants.ACCESS_EXTERNAL_DTD);
                schemaFactoryBuilder.removeAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA);
                XmlDefinerUtils.getInstance().setSchemaFactoryBuilder(schemaFactoryBuilder);

                // set tokenExtractionStategy to get certificate binary data from the report.diagnosticData, by default tokenExtractionStategy is NONE
                validator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_CERTIFICATES_ONLY);
                reports = validator.validateDocument(getValidationPolicy(profileConfig));

                for (String signatureId : reports.getSimpleReport().getSignatureIdList()) {
                    String certId = reports.getDiagnosticData().getSigningCertificateId(signatureId);
                    CertificateWrapper signingCertificate = reports.getDiagnosticData().getUsedCertificateById(certId);
                    X509Certificate signingCertificateX509 = CertUtils.getX509CertificateFromPEMorDER(signingCertificate.getBinaries());
                    SAMLAuthContextType authContext = SupportLibraryUtils.getAuthContextFromCertificate(authContSaciMessageParser, signingCertificateX509);

                    Signature signature = new Signature();
                    signature.setSignerCertificate(signingCertificate.getBinaries());
                    signature.setIssuerId(signingCertificate.getCertificateIssuerDN());
                    signature.setSigningDate(reports.getDiagnosticData().getSignatureDate(signatureId));
                    signature.setSigningAlgorithm(SignatureAlgorithm.getAlgorithm(signingCertificate.getEncryptionAlgorithm(), signingCertificate.getDigestAlgorithm()).getJCEId());
                    signature.setValidFrom(signingCertificate.getNotBefore());
                    signature.setValidTo(signingCertificate.getNotAfter());
                    signature.setSignerId(SupportLibraryUtils.getUserIdFromAuthContext(authContext, profileConfig));
                    signature.setSignerDisplayName(SupportLibraryUtils.getDisplayNameFromAuthContext(authContext));
                    signature.setLevelOfAssurance(SupportLibraryUtils.getLevelOfAssuranceFromAuthContext(apiConfig, authContext));
                    signatures.add(signature);
                }

                for (String signatureId : reports.getSimpleReport().getSignatureIdList()) {
                    Indication indication = reports.getSimpleReport().getIndication(signatureId);
                    if (indication == Indication.TOTAL_PASSED) {
                        validSignatures++;
                    } else if (response.getVerificationErrorCode() == null || response.getVerificationErrorCode() < indication.ordinal()) {
                        response.setVerificationErrorCode(indication.ordinal());
                        response.setVerificationErrorMessages(getMessagesFromList(reports.getSimpleReport().getQualificationErrors(signatureId), "en"));
                    }
                }

                response.setVerifies((validSignatures == reports.getSimpleReport().getSignaturesCount() && validSignatures > 0));

                if (reports.getSimpleReport().getSignaturesCount() > 0) {
                    if (apiConfig.isUseSimpleValidationReport()) {
                        response.setReportData(reports.getXmlSimpleReport().getBytes(StandardCharsets.UTF_8));
                    } else {
                        response.setReportData(reports.getXmlDetailedReport().getBytes(StandardCharsets.UTF_8));
                    }
                    response.setReportMimeType(MimeType.XML.getMimeTypeString());
                } else {
                    response.setReportData(null);
                }
            } else {
                // Failed to initialize signature validator. This could either mean we have an
                // unsigned document or an unsupported signature format.
                response.setVerifies(false);
            }

            response.setSignatures(new Signatures(signatures));

        } catch (Exception e) {
            log.error("Error while verifying signed document: " + e.getMessage());

            if (e instanceof ServerErrorException) {
                throw (ServerErrorException) e;
            } else if (e instanceof ClientErrorException) {
                throw (ClientErrorException) e;
            } else {
                throw (ServerErrorException) ErrorCode.VERIFY_DOCUMENT_FAILED.toException("Failed to verify document: " + e.getMessage());
            }
        }
        return response;
    }

    /**
     * Generate Base64 encoded SignRequest according to Swedish eID framework.
     *
     * @param context                 Security provider context
     * @param transactionId           Transaction ID to use
     * @param documents               Documents to be signed
     * @param signMessage             Message to show during signing process or null if no message should be shown
     * @param user                    User signatory information
     * @param authenticationServiceId identity provider to use during signature process
     * @param consumerURL             URL where the user will be sent when signature process is completed
     * @param config                  Configuration to use when generating request
     * @return Marshalled SignRequest XML-document based on given parameters
     */
    protected synchronized String generateSignRequest(ContextMessageSecurityProvider.Context context, String transactionId, DocumentRequests documents,
                                                      String signMessage, User user, String authenticationServiceId, String consumerURL,
                                                      SupportAPIProfile config, List<Attribute> signatureAttributes) throws IOException, MessageContentException, MessageProcessingException, BaseAPIException, InvalidArgumentException, InternalErrorException, ClassNotFoundException, ParserConfigurationException, SAXException, InvalidCanonicalizerException, CanonicalizationException, CertificateEncodingException, NoSuchAlgorithmException, TransformerException {

        GregorianCalendar requestTime = new GregorianCalendar();
        requestTime.setTime(new Date());
        SignRequestExtensionType signRequestExtensionType = sweEid2ObjectFactory.createSignRequestExtensionType();
        if (StringUtils.isNoneEmpty(signMessage)) {
            signRequestExtensionType.setSignMessage(generateSignMessage(context, signMessage, authenticationServiceId, config));
        }

        signRequestExtensionType.setVersion(config.getSignRequestExtensionVersion());
        signRequestExtensionType.setConditions(generateConditions(requestTime, consumerURL, config));
        signRequestExtensionType.setSigner(generateSigner(user, authenticationServiceId, config));
        signRequestExtensionType.setRequestTime(datatypeFactory.newXMLGregorianCalendar(requestTime));
        signRequestExtensionType.setIdentityProvider(createNameIDType(authenticationServiceId, "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"));
        signRequestExtensionType.setSignService(createNameIDType(config.getSignServiceId(), "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"));
        signRequestExtensionType.setCertRequestProperties(sweEid2ObjectFactory.createCertRequestPropertiesType());
        signRequestExtensionType.getCertRequestProperties().getAuthnContextClassRef().addAll(getAuthnContextClassRefs(authenticationServiceId, config));
        signRequestExtensionType.setSignRequester(createNameIDType(config.getSignRequester(), "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"));
        signRequestExtensionType.getCertRequestProperties().setCertType(config.getCertificateType());
        signRequestExtensionType.setRequestedSignatureAlgorithm(SignatureAlgorithm.forJAVA(config.getSignatureAlgorithm()).getUri());
        signRequestExtensionType.getCertRequestProperties().setRequestedCertAttributes(sweEid2ObjectFactory.createRequestedAttributesType());

        if (config.isEnableAuthnProfile()) {
            signRequestExtensionType.setAuthnProfile(config.getRelatedProfile());
        }

        if (config.getRequestedCertAttributes() != null) {
            for (Map.Entry<String, Map<String, Object>> entry : config.getRequestedCertAttributes().entrySet()) {
                signRequestExtensionType.getCertRequestProperties().getRequestedCertAttributes().getRequestedCertAttribute().add(
                        generateRequestedAttribute(entry.getKey(), entry.getValue(), config.getRelatedProfile())
                );
            }
        }

        JAXBElement<SignRequestExtensionType> signRequestExtension = sweEid2ObjectFactory.createSignRequestExtension(signRequestExtensionType);
        SignTasksType signTasksType = sweEid2ObjectFactory.createSignTasksType();

        for (Object object : documents.documents) {
            if (object instanceof DocumentSigningRequest) {
                DocumentSigningRequest documentSigningRequest = (DocumentSigningRequest) object;
                if (documentSigningRequest.referenceId == null) {
                    documentSigningRequest.referenceId = SupportLibraryUtils.generateReferenceId();
                }
                List<Attribute> preProcessedSignatureAttributes = getSignatureAttributePreProcessor(documentSigningRequest).preProcess(signatureAttributes, documentSigningRequest);
                signTasksType.getSignTaskData().add(generateSignTask(documentSigningRequest, transactionId, getSigningId(user, config), config, preProcessedSignatureAttributes));
            } else if (object instanceof DocumentRef) {
                // TODO: Implement support for signing document by reference
                throw ErrorCode.UNSUPPORTED_OPERATION.toException("Document references not supported");
            } else {
                throw ErrorCode.UNSUPPORTED_OPERATION.toException("Input document type not supported: " + object.getClass().getName());
            }
        }

        JAXBElement<SignTasksType> signTasks = sweEid2ObjectFactory.createSignTasks(signTasksType);
        byte[] signRequest = sweEID2DSSExtensionsMessageParser.genSignRequest(context, transactionId, Constants.SWE_EID_DSS_PROFILE, signRequestExtension, signTasks, true);
        return new String(Base64.encode(signRequest), StandardCharsets.UTF_8);
    }

    /**
     * Apply signature onto a document to create a valid signed document to include in response.
     *
     * @param document                  Original document to apply signature upon.
     * @param signTask                  Sign task containing generated signature information.
     * @param signatureCertificateChain Signature certificate trust chain.
     * @param relatedTransaction        Transaction that is related to the document to sign
     * @param config                    Configuration to use.
     * @return Signed document according to given parameters.
     */
    private synchronized Document signDocument(DocumentSigningRequest document, SignTaskDataType signTask, X509Certificate[] signatureCertificateChain,
                                               TransactionState relatedTransaction, SupportAPIProfile config) throws ClientErrorException, ServerErrorException, MessageContentException, IOException, MessageProcessingException, ParserConfigurationException, SAXException {
        Document signedDocument = null;

        if (document == null) {
            throw (ClientErrorException) ErrorCode.INVALID_DOCUMENT.toException("Document to sign must be specified");
        }

        if (signTask == null) {
            throw (ClientErrorException) ErrorCode.INVALID_SIGN_TASK.toException("Sign task is null, it must be specified");
        }

        if (signatureCertificateChain == null || signatureCertificateChain.length == 0) {
            throw (ServerErrorException) ErrorCode.INVALID_CERTIFICATE_CHAIN.toException("Signature certificate chain missing or empty");
        }

        SignatureForm signatureForm = getSignatureForm(signTask);
        if (signatureForm == null) {
            throw (ClientErrorException) ErrorCode.INVALID_SIGN_TASK.toException("Sign task contains invalid or unsupported signature algorithm (" + signTask.getSigType() + ")");
        }

        try {
            CertificateToken signatureToken = new CertificateToken(signatureCertificateChain[0]);
            SAMLAuthContextType authContext = SupportLibraryUtils.getAuthContextFromCertificate(authContSaciMessageParser, signatureCertificateChain[0]);
            List<CertificateToken> signatureTokenChain = new ArrayList<>();

            for (X509Certificate cert : signatureCertificateChain) {
                signatureTokenChain.add(new CertificateToken(cert));
            }

            DSSDocument dssDocument = DSSLibraryUtils.createDSSDocument(document);
            SigType sigType = SigType.valueOf(getSigTypeFromMimeType(document.getType()));
            AbstractSignatureParameters signatureParameters = getSignatureParameters(signTask, sigType, signatureToken, signatureTokenChain, document, relatedTransaction, config);
            SignatureValue signatureValue = new SignatureValue(SignatureAlgorithm.forXML(signTask.getBase64Signature().getType()), signTask.getBase64Signature().getValue());
            String strongReferenceId = SupportLibraryUtils.generateStrongReferenceId(relatedTransaction.getTransactionId(), document.getReferenceId());
            DSSDocument dssSignedDocument = null;

            switch (sigType) {
                case XML:
                    XAdESSignatureParameters xAdESParameters = (XAdESSignatureParameters) signatureParameters;
                    xAdESParameters.setSignedAdESObject(signTask.getAdESObject().getAdESObjectBytes());
                    dssSignedDocument = xAdESService.signDocument(dssDocument, (XAdESSignatureParameters) signatureParameters, signatureValue);
                    break;
                case PDF:
                    PAdESSignatureParameters pAdESParameters = (PAdESSignatureParameters) signatureParameters;
                    boolean validAttributes = validateVisibleSignatureAttributesFromCache(strongReferenceId);
                    pAdESParameters.setSignerName(getSigningId(relatedTransaction.getUser(), config));
                    if (config.getVisibleSignature().isEnable()) {
                        if (validAttributes) {
                            setVisibleSignature(config, pAdESParameters, pAdESParameters.getSignerName(), strongReferenceId, null);
                        } else {
                            log.warn("Visible signatures are enabled in configuration (enableVisibleSignature) but required signature attributes are missing. The following attributes are required: " +
                                    AvailableSignatureAttributes.VISIBLE_SIGNATURE_POSITION_X + ", " +
                                    AvailableSignatureAttributes.VISIBLE_SIGNATURE_POSITION_Y + ", " +
                                    AvailableSignatureAttributes.VISIBLE_SIGNATURE_WIDTH + ", " +
                                    AvailableSignatureAttributes.VISIBLE_SIGNATURE_HEIGHT);
                        }
                    }
                    pAdESParameters.setSignerName(getSigningId(relatedTransaction.getUser(), config));
                    dssSignedDocument = pAdESService.signDocument(dssDocument, pAdESParameters, signatureValue);
                    break;
                case CMS:
                    dssSignedDocument = cAdESService.signDocument(dssDocument, (CAdESSignatureParameters) signatureParameters, signatureValue);
                    break;
                default:
                    break;
            }

            if (dssSignedDocument != null) {
                String signerId = SupportLibraryUtils.getUserIdFromAuthContext(authContext, config);
                if (signerId == null) {
                    signerId = signatureToken.getSubject().getPrincipal().getName();
                }

                String displayName = SupportLibraryUtils.getDisplayNameFromAuthContext(authContext);
                if (displayName == null) {
                    displayName = CertUtils.getPartFromDN(signatureToken.getSubject().getPrincipal().getName(), "CN");
                }

                Signature signature = new Signature();
                signature.signerCertificate = signatureToken.getEncoded();
                signature.validFrom = signatureToken.getCertificate().getNotBefore();
                signature.validTo = signatureToken.getCertificate().getNotAfter();
                signature.signingDate = signatureParameters.bLevel().getSigningDate();
                signature.setSignerId(signerId);
                signature.setSignerDisplayName(displayName);
                signature.setIssuerId(signatureToken.getIssuerX500Principal().getName());
                signature.signingAlgorithm = SignatureAlgorithm.forXML(signTask.getBase64Signature().getType()).toString();
                signature.levelOfAssurance = SupportLibraryUtils.getLevelOfAssuranceFromAuthContext(apiConfig, authContext);

                signedDocument = new Document();
                signedDocument.setName(document.getName());
                signedDocument.setType(document.getType());
                signedDocument.setReferenceId(document.getReferenceId());
                signedDocument.setSignatures(new Signatures());
                signedDocument.getSignatures().getSigner().add(signature);
                signedDocument.data = IOUtils.toByteArray(dssSignedDocument.openStream());
            }

            if (config.isEnableAutomaticValidation()) {
                try {
                    VerifyDocumentResponse validationInfo = verifyDocument(config, signedDocument);
                    signedDocument.setValidationInfo(validationInfo);
                } catch (Exception e) {
                    log.error("Error while performing automatic validation of document: " + e.getMessage() + ")");
                }
            }

        } catch (DSSException | InvalidArgumentException | InternalErrorException | BaseAPIException e) {
            throw (ServerErrorException) ErrorCode.SIGN_RESPONSE_FAILED.toException("Error while signing document: " + e.getMessage() + ")");
        }

        return signedDocument;
    }

    /**
     * Create Messages instance based on a given list of messages and a
     * corresponding language.
     *
     * @param messageList List of messages.
     * @param language    Language to use.
     * @return Messages instance.
     */
    private Messages getMessagesFromList(List<eu.europa.esig.dss.jaxb.object.Message> messageList, String language) {
        Messages messages = new Messages();
        messages.message = new ArrayList<Message>();
        for (eu.europa.esig.dss.jaxb.object.Message errorMessage : messageList) {
            Message message = new Message();
            message.setText(String.format("%s: %s", errorMessage.getKey(), errorMessage.getValue()));
            message.setLang(language);
            messages.message.add(message);
        }

        return messages;
    }

    /**
     * Get validation policy path to use based on a given
     * profile and the API configuration.
     *
     * @param profile API Profile
     * @return Path to validation policy to use.
     */
    InputStream getValidationPolicy(SupportAPIProfile profile) throws FileNotFoundException {
        InputStream policy = null;
        Path policyPath;
        String policyBasePath = apiConfig.getValidationPolicyDirectory();

        String profilePolicyPath = profile.getValidationPolicy();
        if (!profilePolicyPath.endsWith(".xml")) {
            profilePolicyPath += ".xml";
        }

        if (policyBasePath != null) {
            policyPath = Paths.get(policyBasePath, profilePolicyPath);
        } else {
            policyPath = Paths.get(profilePolicyPath);
        }

        try {
            String policyClassPath = policyPath.toString();
            if (!policyClassPath.startsWith("/")) {
                policyClassPath = String.format("/%s", policyClassPath);
            }

            policy = this.getClass().getResourceAsStream(policyClassPath);
            if (policy == null) {
                policy = new FileInputStream(policyPath.toFile());
            }
        } catch (Exception e) {
            log.error("Error while reading policy file: " + e.getMessage());
        }

        if (policy == null) {
            log.error("Could not load validation policy from path: " + policyPath);
        }

        return policy;
    }

    /**
     * Get certificate verifier instance used during document validation.
     *
     * @return CertificateVerifier to use during validation.
     */
    private CertificateVerifier getCertificateVerifier() {
        if (certificateVerifier == null) {
            if (apiConfig.getCertificateVerifier() == null) {
                certificateVerifier = new CommonCertificateVerifier();
                certificateVerifier.setCrlSource(getCRLSource());
                certificateVerifier.setOcspSource(getOCSPSource());

                if (apiConfig.getTrustedCertificateSource() == null) {
                    log.warn("Verification of documents will not work properly as trusted certificate source is not specified");
                } else {
                    if (apiConfig.getTrustedCertificateSource() instanceof TrustedListsCertificateSourceBuilder) {
                        certificateVerifier.setAIASource(getAIASource());
                        certificateVerifier.setTrustedCertSources(((TrustedListsCertificateSourceBuilder) apiConfig.getTrustedCertificateSource()).getTrustedListsCertificateSource());
                        if (((TrustedListsCertificateSourceBuilder) apiConfig.getTrustedCertificateSource()).getKeyStoreCertificateSource() != null) {
                            CommonTrustedCertificateSource certificateSource = new CommonTrustedCertificateSource();
                            certificateSource.importAsTrusted(((TrustedListsCertificateSourceBuilder) apiConfig.getTrustedCertificateSource()).getKeyStoreCertificateSource());
                            certificateVerifier.addTrustedCertSources(certificateSource);
                        }
                    } else if (apiConfig.getTrustedCertificateSource() instanceof KeyStoreCertificateSource) {
                        CommonTrustedCertificateSource certificateSource = new CommonTrustedCertificateSource();
                        certificateSource.importAsTrusted(apiConfig.getTrustedCertificateSource());
                        certificateVerifier.setTrustedCertSources(certificateSource);
                    }
                }
            } else {
                certificateVerifier = apiConfig.getCertificateVerifier();
            }
        }
        return certificateVerifier;
    }

    /**
     * Get File Cache Data Loader.
     * Using FileCacheDataLoader with CommonsDataLoader and creates a File cache directory.
     *
     * @return DataLoader
     */
    private DataLoader getFileCacheDataLoader() {
        FileCacheDataLoader cacheDataLoader = new FileCacheDataLoader();
        CommonsDataLoader dataLoader = new CommonsDataLoader();

        if (apiConfig.getValidationProxyConfig() != null) {
            dataLoader.setProxyConfig(apiConfig.getValidationProxyConfig());
        }

        cacheDataLoader.setDataLoader(dataLoader);
        cacheDataLoader.setFileCacheDirectory(new File(System.getProperty("java.io.tmpdir")));

        long cacheExpirationTime = apiConfig.getValidationCacheExpirationTimeMS();
        log.info("Setting validation cache expiration time to " + cacheExpirationTime + " ms");
        cacheDataLoader.setCacheExpirationTime(cacheExpirationTime);
        return cacheDataLoader;
    }

    /**
     * Get AIA source to use during document validation.
     *
     * @return Default AIA source
     */
    private DefaultAIASource getAIASource() {
        if (aiaSource == null) {
            log.debug("Initializing AIA loader");
            aiaSource = new DefaultAIASource(getFileCacheDataLoader());
        }

        return aiaSource;
    }

    /**
     * Get CRL source to use during document validation.
     *
     * @return CRL source
     */
    private CRLSource getCRLSource() {
        if (crlSource == null) {
            log.debug("Initializing CRL loader");
            crlSource = new OnlineCRLSource(getFileCacheDataLoader());
        }

        return crlSource;
    }

    /**
     * Get OCSP source to use during document validation.
     *
     * @return OCSP source.
     */
    private OCSPSource getOCSPSource() {
        if (ocspSource == null) {
            log.debug("Initializing OCSP loader");
            OCSPDataLoader dataLoader = new OCSPDataLoader();
            if (apiConfig.getValidationProxyConfig() != null) {
                dataLoader.setProxyConfig(apiConfig.getValidationProxyConfig());
            }
            ocspSource = new OnlineOCSPSource(dataLoader);
        }
        return ocspSource;
    }

    /**
     * Parse and deserialize message.
     *
     * @param context          Related context.
     * @param message          Message content to parse.
     * @param requireSignature If message signature is expected and required.
     * @return Parsed and deserialized message.
     * @throws MessageContentException    If error occurred when parsing the message content.
     * @throws MessageProcessingException If error occurred when processing the message.
     */
    private synchronized Object synchronizedParseMessage(org.certificateservices.messages.ContextMessageSecurityProvider.Context context, byte[] message, boolean requireSignature) throws MessageContentException, MessageProcessingException {
        return sweEID2DSSExtensionsMessageParser.parseMessage(context, message, requireSignature);
    }

    /**
     * Get list of sign tasks within a given signature response.
     *
     * @param response Signature response to read sign tasks from.
     * @return List of sign tasks in given sign response.
     */
    private synchronized List<SignTaskDataType> synchronizedGetSignTasks(SignResponse response) throws InvalidArgumentException {
        return SignTaskHelper.getSignTasks(response);
    }

    /**
     * Create NameIDType instance.
     *
     * @param value  Value of instance.
     * @param format Format of instance.
     * @return NameIDType instance based on given parameters.
     */
    private NameIDType createNameIDType(String value, String format) {
        NameIDType nameIDType = new NameIDType();
        nameIDType.setValue(value);
        nameIDType.setFormat(format);
        return nameIDType;
    }

    /**
     * Get signature form for a given sign task
     *
     * @param signTask Sign task to get signature form for
     * @return Signature form of given sign task
     */
    private SignatureForm getSignatureForm(SignTaskDataType signTask) {
        if (SignTaskHelper.isXadesSignTask(signTask)) {
            return SignatureForm.XAdES;
        } else if (SignTaskHelper.isCadesSignTask(signTask)) {
            return SignatureForm.CAdES;
        } else if (SignTaskHelper.isPadesSignTask(signTask)) {
            return SignatureForm.PAdES;
        } else {
            return null;
        }
    }

    /**
     * Get signing id to use for signature
     *
     * @param user   User performing the signature
     * @param config Configuration to use
     * @return Signing id (displayname) to use for signature.
     */
    protected String getSigningId(User user, SupportAPIProfile config) {
        String signingId = user.getUserId();
        if (config.getUserDisplayNameAttribute() != null && user.getUserAttributes() != null) {
            Attribute userDisplayNameAttribute = null;
            for (Attribute attribute : user.getUserAttributes()) {
                if (attribute.getKey().equals(config.getUserDisplayNameAttribute())) {
                    userDisplayNameAttribute = attribute;
                    break;
                }
            }

            if (userDisplayNameAttribute != null) {
                signingId = userDisplayNameAttribute.getValue();
            }
        }
        return signingId;
    }

    /**
     * Generate sign task for a given document
     *
     * @param document      DocumentSigningRequest containing document to generate sign task for.
     * @param transactionId Transaction ID for signature flow
     * @param signingId     Signing identity (e.g. name) to use when creating signature data-to-be-signed.
     * @param config        Configuration to use
     * @return Sign task for given document data.
     */
    private SignTaskDataType generateSignTask(DocumentSigningRequest document, String transactionId, String signingId,
                                              SupportAPIProfile config, List<Attribute> signatureAttributes) throws InvalidArgumentException, BaseAPIException, IOException, InternalErrorException, ClassNotFoundException, ParserConfigurationException, MessageProcessingException, SAXException, InvalidCanonicalizerException, CanonicalizationException, CertificateEncodingException, NoSuchAlgorithmException, TransformerException {
        SignTaskDataType signTask = sweEid2ObjectFactory.createSignTaskDataType();
        signTask.setSigType(getSigTypeFromMimeType(document.type));
        signTask.setSignTaskId(document.getReferenceId());
        signTask.setToBeSignedBytes(generateToBeSignedBytes(signTask, document, transactionId, signingId, config, signatureAttributes));

        return signTask;
    }

    /**
     * Method to validate the cache contains all required signatureAttributes for a given context ID.
     *
     * @param contextId Context ID in cache to validate.
     * @return true if all required attributes exists in cache, otherwise false.
     */
    protected boolean validateVisibleSignatureAttributesFromCache(String contextId) throws InvalidArgumentException, IOException, InternalErrorException {
        return cacheProvider.get(contextId, VISIBLE_SIGNATURE_POSITION_X) != null &&
                cacheProvider.get(contextId, VISIBLE_SIGNATURE_POSITION_Y) != null &&
                cacheProvider.get(contextId, VISIBLE_SIGNATURE_WIDTH) != null &&
                cacheProvider.get(contextId, VISIBLE_SIGNATURE_HEIGHT) != null;
    }

    /**
     * Generate a MappedAttributeType containing a requested attribute used to represent
     * requests for subject attributes in a signer certificate that is associated with the signer
     * of the generated signature as a result of the sign request.
     * <p>
     * Parameters map may contain the following keys (described in the Swedish eID framework, ELN-0609:3.1.1.1)
     * - samlAttributeName
     * - certAttributeRef
     * - certNameType
     * - required
     *
     * @param friendlyName Name of attribute
     * @param parameters   Attribute parameters
     * @param profile      the profile name
     * @return MappedAttributeType element based on given parameters
     */
    private MappedAttributeType generateRequestedAttribute(String friendlyName, Map<String, Object> parameters, String profile) throws BaseAPIException {
        MappedAttributeType requestedAttribute;
        try {
            requestedAttribute = new MappedAttributeType();
            requestedAttribute.setCertAttributeRef(ConfigUtils.parseString(parameters.get("certAttributeRef"), null, false, null));
            requestedAttribute.setFriendlyName(friendlyName);
            requestedAttribute.setRequired(ConfigUtils.parseBoolean(parameters.get("required"), null, false, null));
            requestedAttribute.setCertNameType(ConfigUtils.parseString(parameters.get("certNameType"), null, false, null));
        } catch (Exception e) {
            throw ErrorCode.INVALID_PROFILE.toException("Invalid parameter specified in profile configuration: " + e.getMessage());
        }

        if (parameters.get("samlAttributeName") instanceof String) {
            PreferredSAMLAttributeNameType preferredSAMLAttributeNameType = new PreferredSAMLAttributeNameType();
            preferredSAMLAttributeNameType.setValue((String) parameters.get("samlAttributeName"));
            requestedAttribute.getSamlAttributeName().add(preferredSAMLAttributeNameType);
        } else if (parameters.get("samlAttributeName") instanceof List) {
            for (Map samlAttributeNameMap : (List<Map<String, String>>) parameters.get("samlAttributeName")) {
                if (samlAttributeNameMap.get("order") != null && !samlAttributeNameMap.get("order").equals("")) {
                    Integer order;
                    try {
                        order = Integer.parseInt(samlAttributeNameMap.get("order").toString());
                    } catch (Exception e) {
                        throw ErrorCode.INVALID_PROFILE.toException(profile + ".requestedCertAttributes.serialNumber." + samlAttributeNameMap.get("value") + " has no-integer order value.");
                    }
                    if (order < 0) {
                        throw ErrorCode.INVALID_PROFILE.toException(profile + ".requestedCertAttributes.serialNumber." + samlAttributeNameMap.get("value") + " has invalid order value. Order must be larger than or equal to 0");
                    }
                    PreferredSAMLAttributeNameType preferredSAMLAttributeNameType = new PreferredSAMLAttributeNameType();
                    preferredSAMLAttributeNameType.setValue((String) samlAttributeNameMap.get("value"));
                    preferredSAMLAttributeNameType.setOrder(order);
                    requestedAttribute.getSamlAttributeName().add(preferredSAMLAttributeNameType);

                } else {
                    PreferredSAMLAttributeNameType preferredSAMLAttributeNameType = new PreferredSAMLAttributeNameType();
                    preferredSAMLAttributeNameType.setValue((String) samlAttributeNameMap.get("value"));
                    requestedAttribute.getSamlAttributeName().add(preferredSAMLAttributeNameType);
                }
            }
        } else {
            throw ErrorCode.INVALID_PROFILE.toException("The samlAttributeName under " + profile + ".requestedCertAttributes must be a string or a list of map.");
        }

        return requestedAttribute;
    }

    /**
     * Get TSP source from cache if possible or create new one.
     *
     * @param timeStampServer Timestamp server
     * @return TSP source for given timestamp server.
     */
    private TSPSource getTspSource(String timeStampServer) {
        TSPSource tspSource = apiConfig.getTspSource();
        if (tspSource == null) {
            tspSource = onlineTSPSources.get(timeStampServer);
            if (tspSource == null) {
                tspSource = new OnlineTSPSource(timeStampServer);
                onlineTSPSources.put(timeStampServer, tspSource);
            }
        }
        return tspSource;
    }

    /**
     * Generate data to be signed for a given document and create any needed AdES-object
     *
     * @param signTask      Related Signtask that will be updated during the process.
     * @param document      DocumentSigningRequest containing document to be signed
     * @param transactionId Transaction ID for signature flow
     * @param signingId     Signing identity (e.g. name) to use when creating signature data-to-be-signed.
     * @param config        Configuration to use
     * @return Data to be signed for the given document
     */
    private byte[] generateToBeSignedBytes(SignTaskDataType signTask, DocumentSigningRequest document, String transactionId,
                                           String signingId, SupportAPIProfile config, List<Attribute> signatureAttributes) throws BaseAPIException, InvalidArgumentException, IOException, InternalErrorException, ClassNotFoundException, ParserConfigurationException, MessageProcessingException, SAXException, InvalidCanonicalizerException, CanonicalizationException, CertificateEncodingException, NoSuchAlgorithmException, TransformerException {
        SigType sigType = SigType.valueOf(getSigTypeFromMimeType(document.getType()));
        DSSDocument dssDocument = DSSLibraryUtils.createDSSDocument(document);
        AbstractSignatureParameters dssParameters = getSignatureParameters(sigType, config);

        switch (sigType) {
            case XML:
                if (!config.getXadesSignatureLevel().equals(SignatureLevel.XAdES_BASELINE_B.toString())) {
                    xAdESService.setTspSource(getTspSource(config.getTimeStampServer()));
                }
                signTask.setToBeSignedBytes(xAdESService.getDataToSign(dssDocument, (XAdESSignatureParameters) dssParameters).getBytes());
                break;
            case PDF:
                if (!config.getPadesSignatureLevel().equals(SignatureLevel.PAdES_BASELINE_B.toString())) {
                    pAdESService.setTspSource(getTspSource(config.getTimeStampServer()));
                }
                PAdESSignatureParameters pAdESParameters = (PAdESSignatureParameters) dssParameters;
                pAdESParameters.setSignerName(signingId);

                if (config.getVisibleSignature().isEnable()) {
                    setVisibleSignature(config, pAdESParameters, signingId, SupportLibraryUtils.generateStrongReferenceId(transactionId, document.getReferenceId()), signatureAttributes);
                }

                pAdESService.setPdfObjFactory(new PdfBoxSupportObjectFactory());
                signTask.setToBeSignedBytes(pAdESService.getDataToSign(dssDocument, pAdESParameters).getBytes());
                break;
            case CMS:
                if (!config.getCadesSignatureLevel().equals(SignatureLevel.CAdES_BASELINE_B.toString())) {
                    cAdESService.setTspSource(getTspSource(config.getTimeStampServer()));
                }
                signTask.setToBeSignedBytes(cAdESService.getDataToSign(dssDocument, (CAdESSignatureParameters) dssParameters).getBytes());
                break;
            default:
                break;
        }

        // Generate Base AdES-object if needed
        AdESType adESType = getAdESType(sigType, config);
        signTask.setAdESType(adESType.name());

        // XAdES is the only signature type that has a separate AdES-object.
        if (adESType == AdESType.BES && sigType == SigType.XML) {
            SignTaskHelper.createNewXadesObject(signTask, config.getSignatureAlgorithm(), null, dssParameters.bLevel().getSigningDate());
        }

        // Store signing time in cache
        TransactionState transactionState = fetchTransactionState(transactionId);
        if (transactionState == null) {
            transactionState = new TransactionState();
        }
        transactionState.getSigningTime().put(document.referenceId, dssParameters.bLevel().getSigningDate());
        storeTransactionState(transactionId, transactionState);

        log.debug("Generated ToBeSignedBytes (" + sigType.name() + ") = " + new String(Base64.encode(signTask.getToBeSignedBytes())));
        return signTask.getToBeSignedBytes();
    }

    /**
     * Get signature attribute preprocessor to use for a document.
     *
     * @param document Document to get signature attribute pre processor for.
     * @return Signature attribute pre processor to use for given document.
     * @throws ClientErrorException If an error occurred while retrieving signature attribute pre processor.
     */
    protected SignatureAttributePreProcessor getSignatureAttributePreProcessor(DocumentSigningRequest document) throws ClientErrorException {
        SigType sigType = SigType.valueOf(getSigTypeFromMimeType(document.getType()));

        if (signatureAttributePreProcessors.get(sigType) == null) {
            switch (sigType) {
                case XML:
                    signatureAttributePreProcessors.put(sigType, new XAdESSignatureAttributePreProcessor());
                    break;
                case PDF:
                    signatureAttributePreProcessors.put(sigType, new PAdESSignatureAttributePreProcessor());
                    break;
                case CMS:
                    signatureAttributePreProcessors.put(sigType, new CAdESSignatureAttributePreProcessor());
                    break;
                default:
                    throw (ClientErrorException) ErrorCode.INVALID_MIMETYPE.toException("Invalid mimetype in document signing request");
            }
        }
        return signatureAttributePreProcessors.get(sigType);
    }

    /**
     * Method to set parameters for the visible signature.
     *
     * @param config              Profile configuration.
     * @param parameters          Signature parameters to update with parameters for visible signature.
     * @param signerName          Name of signatory.
     * @param contextId           Context ID in cache to use for the visible signature attributes.
     * @param signatureAttributes Related signature attributes.
     */
    protected void setVisibleSignature(SupportAPIProfile config, PAdESSignatureParameters parameters, String signerName,
                                       String contextId, List<Attribute> signatureAttributes) throws BaseAPIException {
        try {
            SignatureImageParameters imageParameters = getImageParameters(contextId, signatureAttributes);

            if (config.getVisibleSignature().isShowLogo()) {
                DSSDocument logoDocument = null;
                InputStream logoStream = this.getClass().getResourceAsStream(config.getVisibleSignature().getLogoImage());
                if (logoStream == null) {
                    File file = new File(config.getVisibleSignature().getLogoImage());
                    if (!file.exists() || !file.isFile() || !file.canRead()) {
                        log.error("The provided logo image path for visible signature is not valid (" + config.getVisibleSignature().getLogoImage() + "). Check if the provided path points to an existing file and it has read permission. Logo image will not be used.");
                    } else {
                        log.debug("Using logo image from file system: " + config.getVisibleSignature().getLogoImage());
                        logoDocument = new InMemoryDocument(new FileInputStream(file));
                    }
                } else {
                    log.debug("Using logo image from classpath: " + config.getVisibleSignature().getLogoImage());
                    logoDocument = new InMemoryDocument(logoStream, null);
                }

                if (logoDocument != null) {
                    imageParameters.setImage(logoDocument);
                }
            }

            if(cacheProvider.get(contextId, Constants.VISIBLE_SIGNATURE_REQUEST_TIME) == null){
                try {
                    SimpleDateFormat sdf = new SimpleDateFormat(config.getVisibleSignature().getTimeStampFormat());
                    cacheProvider.set(contextId, Constants.VISIBLE_SIGNATURE_REQUEST_TIME, sdf.format(new Date()));
                } catch(Exception e) {
                    throw ErrorCode.INVALID_CONFIGURATION.toException("Invalid configuration value for timeStampFormat: " + config.getVisibleSignature().getTimeStampFormat() + " (" + e.getMessage() + ")");
                }
            }

            StringBuilder signatureText = new StringBuilder();
            if (config.getVisibleSignature().isShowHeadline()) {
                signatureText.append(config.getVisibleSignature().getHeadlineText()).append("\n");
            }

            String signerLabel = config.getVisibleSignature().getSignerLabel().trim();
            if (signerLabel.length() > 0) {
                signatureText.append(signerLabel).append(": ");
            }
            signatureText.append(signerName).append("\n");

            String timeStampLabel = config.getVisibleSignature().getTimeStampLabel().trim();
            if (timeStampLabel.length() > 0) {
                signatureText.append(timeStampLabel).append(": ");
            }
            signatureText.append(cacheProvider.get(contextId, Constants.VISIBLE_SIGNATURE_REQUEST_TIME));

            SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
            textParameters.setText(signatureText.toString());
            textParameters.setSignerTextPosition(SignerTextPosition.RIGHT);
            textParameters.setBackgroundColor(ColorParser.parse(config.getVisibleSignature().getBackgroundColor()));
            textParameters.setTextColor(ColorParser.parse(config.getVisibleSignature().getFontColor()));

            if (config.getVisibleSignature().getFont() != null) {
                DSSDocument fontDocument = null;
                InputStream fontStream = this.getClass().getResourceAsStream(config.getVisibleSignature().getFont());
                if (fontStream == null) {
                    File file = new File(config.getVisibleSignature().getFont());
                    if (!file.exists() || !file.isFile() || !file.canRead()) {
                        log.error("The provided font file path for visible signature is not valid (" + config.getVisibleSignature().getFont() + "). Check if the provided path points to an existing file and it has read permission. Logo image will not be used.");
                    } else {
                        log.debug("Using font file from file system: " + config.getVisibleSignature().getFont());
                        fontDocument = new InMemoryDocument(new FileInputStream(file));
                    }
                } else {
                    log.debug("Using font file from classpath: " + config.getVisibleSignature().getFont());
                    fontDocument = new InMemoryDocument(fontStream, null);
                }

                if (fontDocument != null) {
                    textParameters.setFont(new DSSFileFont(fontDocument));
                }
            }
            textParameters.getFont().setSize(config.getVisibleSignature().getFontSize());
            textParameters.setPadding(config.getVisibleSignature().getTextPadding());
            imageParameters.setTextParameters(textParameters);
            parameters.setImageParameters(imageParameters);
        } catch (Exception e) {
            log.error("Can't set visible signature parameters for the PAdESSignatureParameters. Message: " + e.getMessage());
            throw ErrorCode.SIGN_REQUEST_FAILED.toException(e, messageSource);
        }
    }

    /**
     * Store transaction state in cache service with TTL from configuration or default.
     *
     * @param transactionId Transaction ID that will be used as cache key
     * @param state         Transaction state to save for the given relay state
     * @return Stored state
     */
    protected TransactionState storeTransactionState(String transactionId, TransactionState state) throws IOException, InvalidArgumentException, InternalErrorException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(state);
        MetaData metaData = new MetaData();
        metaData.setTimeToLive(Constants.DEFAULT_TRANSACTION_TTL);
        cacheProvider.set(transactionId, baos.toByteArray(), metaData);

        return state;
    }

    /**
     * Fetch transaction state from cache service
     *
     * @param transactionId Transaction ID to fetch transaction state for
     * @return Transaction state related to given relay state, or null if not found.
     */
    protected TransactionState fetchTransactionState(String transactionId) throws InvalidArgumentException, IOException, InternalErrorException, ClassNotFoundException {
        byte[] serializedState = cacheProvider.getBinary(transactionId);
        if (serializedState != null) {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedState)) {
                protected Class<?> resolveClass(ObjectStreamClass objectStreamClass) throws IOException, ClassNotFoundException {
                    return Class.forName(objectStreamClass.getName(), true, V2SupportServiceAPI.class.getClassLoader());
                }
            };
            return (TransactionState) ois.readObject();
        }

        return null;
    }

    /**
     * Get AdESType for a given signature type based on a given configuration.
     *
     * @param sigType Signature type to get AdESType for
     * @param config  Configuration that is used
     * @return The AdESType to use for a given signature type and configuration.
     */
    private AdESType getAdESType(SigType sigType, SupportAPIProfile config) {
        AdESType adESType = AdESType.None;

        switch (sigType) {
            case XML:
                if (!config.getXadesSignatureLevel().equals(SignatureLevel.XML_NOT_ETSI.toString())) {
                    adESType = AdESType.BES;
                }
                break;
            case PDF:
                if (!config.getPadesSignatureLevel().equals(SignatureLevel.PDF_NOT_ETSI.toString())) {
                    adESType = AdESType.BES;
                }
                break;
            case CMS:
                if (!config.getCadesSignatureLevel().equals(SignatureLevel.CMS_NOT_ETSI.toString())) {
                    adESType = AdESType.BES;
                }
                break;
            default:
                break;
        }
        return adESType;
    }

    /**
     * Get signature parameters shared by both request and response flow.
     *
     * @param sigType Signature type to get parameters for.
     * @param config  Configuration to use.
     * @return Base signature parameters to use when creating requests and responses.
     */
    AbstractSignatureParameters getBaseSignatureParameters(SigType sigType, SupportAPIProfile config) throws ClientErrorException {
        AbstractSignatureParameters parameters;
        switch (sigType) {
            case CMS:
                CAdESSignatureParameters cp = new CAdESSignatureParameters();
                cp.setSignatureLevel(SignatureLevel.valueByName(config.getCadesSignatureLevel()));
                cp.setSignaturePackaging(SignaturePackaging.valueOf(config.getCadesSignaturePacking()));
                parameters = cp;
                break;
            case XML:
                XAdESSignatureParameters xp = new XAdESSignatureParameters();
                xp.setSignatureLevel(SignatureLevel.valueByName(config.getXadesSignatureLevel()));
                xp.setSignaturePackaging(SignaturePackaging.valueOf(config.getXadesSignaturePacking()));
                xp.setSigningCertificateDigestMethod(SignatureAlgorithm.forJAVA(config.getSignatureAlgorithm()).getDigestAlgorithm());
                xp.setSignedInfoCanonicalizationMethod(config.getXadesCanonicalizationAlgorithmURI());
                xp.setSignedPropertiesCanonicalizationMethod(config.getXadesCanonicalizationAlgorithmURI());
                xp.setXPathLocationString(config.getXadesXPathLocationString());
                parameters = xp;
                break;
            case PDF:
                PAdESSignatureParameters pp = new PAdESSignatureParameters();
                pp.setSignatureLevel(SignatureLevel.valueByName(config.getPadesSignatureLevel()));
                parameters = pp;
                break;
            default:
                throw (ClientErrorException) ErrorCode.UNSUPPORTED_SIGNATURE_TYPE.toException("Signature type not supported (" + sigType.name() + ")");
        }
        return parameters;
    }

    /**
     * Get signature parameters to use when creating request, depending on signature type and configuration
     *
     * @param sigType Signature type to get parameters for.
     * @param config  Configuration to use.
     * @return Signature parameters to use when creating request
     */
    protected AbstractSignatureParameters getSignatureParameters(SigType sigType, SupportAPIProfile config) throws ClientErrorException {
        if (config.getSignatureAlgorithm() == null) {
            throw (ClientErrorException) ErrorCode.INVALID_CONFIGURATION.toException("Signature algorithm is not set in profile " + config.getRelatedProfile());
        }

        AbstractSignatureParameters parameters = getBaseSignatureParameters(sigType, config);
        parameters.setGenerateTBSWithoutCertificate(true);
        parameters.bLevel().setSigningDate(DateUtils.round(new Date(), Calendar.SECOND));
        parameters.setEncryptionAlgorithm(SignatureAlgorithm.forJAVA(config.getSignatureAlgorithm()).getEncryptionAlgorithm());
        parameters.setDigestAlgorithm(SignatureAlgorithm.forJAVA(config.getSignatureAlgorithm()).getDigestAlgorithm());
        return parameters;
    }

    /**
     * Get signature parameters to use when creating response, depending on signature type and configuration
     *
     * @param sigType             Signature type to get parameters for.
     * @param signatureToken      Signature token that was used when generating the signature
     * @param signatureTokenChain Signature token trust chain
     * @param relatedDocument     Related document to get parameters for
     * @param relatedTransaction  Related transaction containing the document to get parameters for
     * @param config              Configuration to use.
     * @return Signature parameters to use when creating response.
     */
    private AbstractSignatureParameters getSignatureParameters(SignTaskDataType signTask, SigType sigType, CertificateToken signatureToken, List<CertificateToken> signatureTokenChain,
                                                               DocumentSigningRequest relatedDocument, TransactionState relatedTransaction, SupportAPIProfile config) throws ClientErrorException, ParserConfigurationException, IOException, SAXException {
        AbstractSignatureParameters parameters = getBaseSignatureParameters(sigType, config);
        parameters.setSigningCertificate(signatureToken);
        parameters.setCertificateChain(signatureTokenChain);
        parameters.setSignedData(signTask.getToBeSignedBytes());

        if (sigType == SigType.XML && relatedTransaction.getSigningTime().get(relatedDocument.referenceId) == null) {
            parameters.bLevel().setSigningDate(SignTaskHelper.getXadesSigningTime(signTask));
        } else {
            parameters.bLevel().setSigningDate(relatedTransaction.getSigningTime().get(relatedDocument.referenceId));
        }

        parameters.setSignWithExpiredCertificate(config.isAllowSignWithExpiredCertificate());
        if (parameters.isSignWithExpiredCertificate()) {
            log.warn("Signing with expired certificate is enabled in profile. Make sure this is a conscious choice.");
        }

        return parameters;
    }

    private SignatureImageParameters getImageParameters(String contextId, List<Attribute> signatureAttributes) throws BaseAPIException {
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        try {
            // First priority is to use parameters from cache if available, if not we setup default
            // values that then can be overridden by any given signature attributes.
            SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
            fieldParameters.setOriginX(getAttributeAsFloatAndStoreInCache(contextId, VISIBLE_SIGNATURE_POSITION_X, cacheProvider.get(contextId, VISIBLE_SIGNATURE_POSITION_X), DEFAULT_VISIBLE_SIGNATURE_POSITION_X));
            fieldParameters.setOriginY(getAttributeAsFloatAndStoreInCache(contextId, VISIBLE_SIGNATURE_POSITION_Y, cacheProvider.get(contextId, VISIBLE_SIGNATURE_POSITION_Y), DEFAULT_VISIBLE_SIGNATURE_POSITION_Y));
            fieldParameters.setWidth(getAttributeAsIntAndStoreInCache(contextId, VISIBLE_SIGNATURE_WIDTH, cacheProvider.get(contextId, VISIBLE_SIGNATURE_WIDTH), DEFAULT_VISIBLE_SIGNATURE_WIDTH));
            fieldParameters.setHeight(getAttributeAsIntAndStoreInCache(contextId, VISIBLE_SIGNATURE_HEIGHT, cacheProvider.get(contextId, VISIBLE_SIGNATURE_HEIGHT), DEFAULT_VISIBLE_SIGNATURE_HEIGHT));
            fieldParameters.setPage(getAttributeAsIntAndStoreInCache(contextId, VISIBLE_SIGNATURE_PAGE, cacheProvider.get(contextId, VISIBLE_SIGNATURE_PAGE), DEFAULT_VISIBLE_SIGNATURE_PAGE));
            imageParameters.setFieldParameters(fieldParameters);

            if (signatureAttributes != null) {
                for (Attribute it : signatureAttributes) {
                    if (Objects.equals(it.getKey(), VISIBLE_SIGNATURE_POSITION_X)) {
                        fieldParameters.setOriginX(getAttributeAsFloatAndStoreInCache(contextId, it.getKey(), it.getValue(), null));
                    } else if (Objects.equals(it.getKey(), VISIBLE_SIGNATURE_POSITION_Y)) {
                        fieldParameters.setOriginY(getAttributeAsFloatAndStoreInCache(contextId, it.getKey(), it.getValue(), null));
                    } else if (Objects.equals(it.getKey(), VISIBLE_SIGNATURE_WIDTH)) {
                        fieldParameters.setWidth(getAttributeAsIntAndStoreInCache(contextId, it.getKey(), it.getValue(), null));
                    } else if (Objects.equals(it.getKey(), VISIBLE_SIGNATURE_HEIGHT)) {
                        fieldParameters.setHeight(getAttributeAsIntAndStoreInCache(contextId, it.getKey(), it.getValue(), null));
                    } else if (Objects.equals(it.getKey(), VISIBLE_SIGNATURE_PAGE)) {
                        fieldParameters.setPage(getAttributeAsIntAndStoreInCache(contextId, it.getKey(), it.getValue(), null));
                    } else {
                        log.info("Ignore attribute: " + it.getKey() + " for visible signature image settings.");
                    }
                }

                // Perform some basic validation on the attributes to fail early.
                if (fieldParameters.getOriginX() <= 0) {
                    throw ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException("Make sure attribute: " + VISIBLE_SIGNATURE_POSITION_X + " is configured with a value equal or larger than 0.");
                } else if (fieldParameters.getOriginY() <= 0) {
                    throw ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException("Make sure attribute: " + VISIBLE_SIGNATURE_POSITION_Y + " is configured with a value equal or larger than 0.");
                } else if (fieldParameters.getWidth() != 0 && fieldParameters.getHeight() != 0) {
                    if (fieldParameters.getWidth() < 180) {
                        throw ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException("Make sure attribute: " + VISIBLE_SIGNATURE_WIDTH + " is configured with a value larger than 180. The minimum image size is: 180*40.");
                    } else if (fieldParameters.getHeight() < 40) {
                        throw ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException("Make sure attribute: " + VISIBLE_SIGNATURE_HEIGHT + " is configured with a value larger than 40. The minimum image size is: 180*40.");
                    }
                }

                imageParameters.setFieldParameters(fieldParameters);
            }

            return imageParameters;
        } catch (Exception e) {
            log.error("Can't set visible signature parameters for the PAdESSignatureParameters. Message: " + e.getMessage());
            throw ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException(e, messageSource);
        }
    }

    /**
     * Parse string attribute value as integer and store attribute in cache.
     *
     * @param contextId      Cache context ID to use when storing attribute.
     * @param attributeName  Name of the attribute.
     * @param attributeValue Value of the attribute as string.
     * @param defaultValue   Default value to use if attribute value is empty or null.
     * @return Attribute value as an integer.
     * @throws InvalidParameterException If attribute value could not be parsed as an integer and default value is null.
     */
    private int getAttributeAsIntAndStoreInCache(String contextId, String attributeName, String attributeValue, String defaultValue) throws InvalidParameterException, BaseAPIException, InvalidArgumentException, IOException, InternalErrorException {
        int value;
        if (attributeValue == null || attributeValue.isEmpty()) {
            if (defaultValue != null) {
                attributeValue = defaultValue;
            } else {
                throw ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException("Invalid sign attribute configured. Can't set " + attributeName + " with empty value or null.");
            }
        }
        try {
            value = Integer.parseInt(attributeValue);
        } catch (Exception ignored) {
            throw ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException("Invalid sign attribute " + attributeName + "=" + attributeValue + " configured. Can't convert " + attributeValue + " to integer.");
        }
        cacheProvider.set(contextId, attributeName, attributeValue);
        return value;
    }

    /**
     * Parse string attribute value as float and store attribute in cache.
     *
     * @param contextId      Cache context ID to use when storing attribute.
     * @param attributeName  Name of the attribute.
     * @param attributeValue Value of the attribute as string.
     * @param defaultValue   Default value to use if attribute value is empty or null.
     * @return Attribute value as a float.
     * @throws InvalidParameterException If attribute value could not be parsed as a float and default value is null.
     */
    private float getAttributeAsFloatAndStoreInCache(String contextId, String attributeName, String attributeValue, String defaultValue) throws InvalidParameterException, BaseAPIException, InvalidArgumentException, IOException, InternalErrorException {
        float value;
        if (attributeValue == null || attributeValue.isEmpty()) {
            if (defaultValue != null) {
                attributeValue = defaultValue;
            } else {
                throw ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException("Invalid sign attribute configured. Can't set " + attributeName + " with empty value or null.");
            }
        }
        try {
            value = Float.parseFloat(attributeValue);
        } catch (Exception ignored) {
            throw ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException("Invalid sign attribute " + attributeName + "=" + attributeValue + " configured. Can't convert " + attributeValue + " to float value.");
        }
        cacheProvider.set(contextId, attributeName, attributeValue);
        return value;
    }

    /**
     * Method to validate the input signatureAttributes that contains all required attributes
     */
    protected boolean validateVisibleSignatureAttributes(List<Attribute> signatureAttributes) {
        if (signatureAttributes == null || signatureAttributes.size() < 4) {
            return false;
        }

        List<String> requiredAttributeKeys = new ArrayList<>(Arrays.asList(
                AvailableSignatureAttributes.VISIBLE_SIGNATURE_POSITION_X,
                AvailableSignatureAttributes.VISIBLE_SIGNATURE_POSITION_Y,
                AvailableSignatureAttributes.VISIBLE_SIGNATURE_WIDTH,
                AvailableSignatureAttributes.VISIBLE_SIGNATURE_HEIGHT
        ));

        List<String> attributeKeys = new ArrayList<>();
        for (Attribute a : signatureAttributes) {
            attributeKeys.add(a.getKey());
        }

        return attributeKeys.containsAll(requiredAttributeKeys);
    }

    /**
     * Get signature type from a given document mime type.
     *
     * @param mimeType
     * @return Signature type ("XML", "PDF" or "CMS") for given mime type.
     */
    protected String getSigTypeFromMimeType(String mimeType) {
        if (mimeType.equals(MimeType.XML.getMimeTypeString())) {
            return SigType.XML.name();
        } else if (mimeType.equals(MimeType.PDF.getMimeTypeString())) {
            return SigType.PDF.name();
        }

        return SigType.CMS.name();
    }

    /**
     * Generate SignMessage to be shown to user before signing
     *
     * @param message       Message to display
     * @param displayEntity The EntityID of the entity responsible for displaying the sign message to the signer.
     * @return SignMessageType element based on given parameters
     */
    protected SignMessageType generateSignMessage(ContextMessageSecurityProvider.Context context, String message, String displayEntity, SupportAPIProfile config) throws UnsupportedEncodingException, MessageProcessingException {
        SignMessageType signMessage;
        SignMessageMimeType mimeType;

        String configuredMimeType = config.getSignMessageMimeType();
        if (configuredMimeType != null && EnumUtils.isValidEnum(SignMessageMimeType.class, configuredMimeType.toUpperCase())) {
            mimeType = SignMessageMimeType.valueOf(configuredMimeType.toUpperCase());
        } else {
            log.error("Invalid mimetype for sign messages specified in configuration: " + config.getSignMessageMimeType() + ". Using 'text' as fallback.");
            mimeType = SignMessageMimeType.TEXT;
        }

        if (config.isUseEncryptedSignMessage()) {
            List<X509Certificate> signMessageRecipients = apiConfig.getEncryptedSignMessageRecipients().get(displayEntity);
            signMessage = sweEID2DSSExtensionsMessageParser.genSignEncryptedMessage(context, config.isSignMessageMustShow(), displayEntity, mimeType, message.getBytes(StandardCharsets.UTF_8), null, signMessageRecipients);
        } else {
            signMessage = sweEID2DSSExtensionsMessageParser.genSignMessage(config.isSignMessageMustShow(), displayEntity, mimeType, message.getBytes(StandardCharsets.UTF_8), null);
        }

        return signMessage;
    }

    /**
     * Generate Signer element based on user data
     *
     * @param user User to generate signer element from
     * @return Signer AttributeStatementType element based on given user data
     */
    private AttributeStatementType generateSigner(User user, String authenticationServiceId, SupportAPIProfile config) throws ServerErrorException {
        AttributeStatementType attributeStatementType = saml2ObjectFactory.createAttributeStatementType();

        // Add the mandatory userId signer attribute before processing any additional attributes.
        String userIdAttributeName = getUserIdAttributeMapping(authenticationServiceId, config);
        attributeStatementType.getAttributeOrEncryptedAttribute().add(generateSignerAttribute(userIdAttributeName, user.getUserId()));

        // Add any additional signer attributes defined in configuration.
        if (config.getSignerAttributes() != null) {

            for (Map.Entry<String, Map<String, Object>> entry : config.getSignerAttributes().entrySet()) {

                Attribute userAttribute = null;
                if (user.getUserAttributes() != null) {
                    for (Attribute attribute : user.getUserAttributes()) {
                        if (attribute.getKey().equals(entry.getValue().get("userAttributeMapping"))) {
                            userAttribute = attribute;
                            break;
                        }
                    }
                }

                if (userAttribute == null && (boolean) entry.getValue().get("required")) {
                    throw (ServerErrorException) ErrorCode.MISSING_CONFIGURATION.toException("Missing required user attribute, defined in signerAttributes configuration: " + entry.getValue().get("userAttributeMapping"));
                } else if (userAttribute != null) {
                    attributeStatementType.getAttributeOrEncryptedAttribute().add(generateSignerAttribute((String) entry.getValue().get("samlAttributeName"), userAttribute.getValue()));
                }
            }
        }

        return attributeStatementType;
    }

    /**
     * Get list of AuthnContextClassRefs to request for a given authentication service.
     *
     * @param authenticationServiceId Authentication service identifier to get AuthnContextClassRefs for.
     * @param config                  Support service configuration to use.
     * @return List of AuthnContextClassRefs to request.
     */
    private List<String> getAuthnContextClassRefs(String authenticationServiceId, SupportAPIProfile config) {
        List<String> accRefs = new ArrayList<>();

        if (config.getAuthnContextClassRef() != null) {
            log.warn("Profile configuration 'authnContextClassRef' is deprecated. Please remove it and use 'defaultAuthnContextClassRefs' instead.");
            accRefs.add(config.getAuthnContextClassRef());
        }

        // We allow both singular and plural definitions of what AuthnContextClassRef(s) to request
        // for the given authentication provider, for both default values and for explicit values
        // configured for each individual authentication provider.

        if (config.getDefaultAuthnContextClassRef() != null) {
            if (!accRefs.contains(config.getDefaultAuthnContextClassRef())) {
                accRefs.add(config.getDefaultAuthnContextClassRef());
            }
        }

        if (config.getDefaultAuthnContextClassRefs() != null) {
            for (String ref : config.getDefaultAuthnContextClassRefs()) {
                if (!accRefs.contains(ref)) {
                    accRefs.add(ref);
                }
            }
        }

        // If any explicit values are defined for the individual authenticatioon providers
        // then they will override any default values previously defined.

        List<String> explicitAccRefs = new ArrayList<>();
        if (config.getTrustedAuthenticationServices() != null) {
            for (Map.Entry<String, Map<String, Object>> entry : config.getTrustedAuthenticationServices().entrySet()) {
                if (entry.getValue().get("entityId").equals(authenticationServiceId)) {
                    if (entry.getValue().get("authnContextClassRef") != null) {
                        explicitAccRefs.add((String) entry.getValue().get("authnContextClassRef"));
                    } else if (entry.getValue().get("authnContextClassRefs") != null) {
                        for (String ref : (List<String>) entry.getValue().get("authnContextClassRefs")) {
                            if (!explicitAccRefs.contains(ref)) {
                                explicitAccRefs.add(ref);
                            }
                        }
                    }
                }
            }
        }

        return (explicitAccRefs.isEmpty() ? accRefs : explicitAccRefs);
    }

    private String getUserIdAttributeMapping(String authenticationServiceId, SupportAPIProfile config) {
        if (config.getUserIdAttributeMapping() != null) {
            log.warn("Profile configuration 'userIdAttributeMapping' is deprecated. Please remove it and use 'defaultUserIdAttributeMapping' instead.");
        }

        String userIdAttributeMapping = config.getDefaultUserIdAttributeMapping();
        if (userIdAttributeMapping == null) {
            userIdAttributeMapping = config.getUserIdAttributeMapping();
        }

        if (config.getTrustedAuthenticationServices() != null) {
            for (Map.Entry<String, Map<String, Object>> entry : config.getTrustedAuthenticationServices().entrySet()) {
                if (entry.getValue().get("entityId").equals(authenticationServiceId) && entry.getValue().get("userIdAttributeMapping") != null) {
                    userIdAttributeMapping = (String) entry.getValue().get("userIdAttributeMapping");
                }
            }
        }

        return userIdAttributeMapping;
    }


    private AttributeType generateSignerAttribute(String name, String value) {
        AttributeType attributeType = saml2ObjectFactory.createAttributeType();
        attributeType.setName(name);
        attributeType.getAttributeValue().add(value);
        return attributeType;
    }

    /**
     * Generate conditions that contains information about validity and consumer URL.
     *
     * @param requestTime Time the signature was requested
     * @param consumerURL Consumer URL that was requested
     * @return ConditionsType element based on given parameters
     */
    private ConditionsType generateConditions(GregorianCalendar requestTime, String consumerURL, SupportAPIProfile config) throws ServerErrorException {
        validateConsumerURL(consumerURL, config);
        ConditionsType conditionsType = saml2ObjectFactory.createConditionsType();
        AudienceRestrictionType audienceRestriction = saml2ObjectFactory.createAudienceRestrictionType();
        audienceRestriction.getAudience().add(consumerURL);
        conditionsType.getConditionOrAudienceRestrictionOrOneTimeUse().add(audienceRestriction);
        conditionsType.setNotBefore(datatypeFactory.newXMLGregorianCalendar(getNotBefore(requestTime, config)));
        conditionsType.setNotOnOrAfter(datatypeFactory.newXMLGregorianCalendar(getNotOnOrAfter(requestTime, config)));
        return conditionsType;
    }

    /**
     * Get not-before value to use depending on configured overlap
     *
     * @param requestTime Time when the request was performed
     * @return Value of not-before to use within sign request
     */
    private GregorianCalendar getNotBefore(GregorianCalendar requestTime, SupportAPIProfile config) {
        GregorianCalendar notBefore = new GregorianCalendar();
        notBefore.setTime(requestTime.getTime());
        notBefore.add(GregorianCalendar.MINUTE, -config.getSignatureValidityOverlapMinutes());
        return notBefore;
    }

    /**
     * Get not-on-or-after value to use depending on configured validity
     *
     * @param requestTime Time when the request was performed
     * @return Value of not-on-or-after to use within sign request
     */
    private GregorianCalendar getNotOnOrAfter(GregorianCalendar requestTime, SupportAPIProfile config) {
        GregorianCalendar notOnOrAfter = new GregorianCalendar();
        notOnOrAfter.setTime(requestTime.getTime());
        notOnOrAfter.add(GregorianCalendar.MINUTE, config.getSignatureValidityMinutes());
        return notOnOrAfter;
    }

    /**
     * Ensures that a transaction ID is valid to use in the system.
     *
     * @param transactionId transaction ID to validate
     * @throws ClientErrorException if given transaction ID is not valid
     */
    private void validateTransactionId(String transactionId) throws ClientErrorException {
        if (transactionId == null || transactionId.length() < 32) {
            throw (ClientErrorException) ErrorCode.UNSUPPORTED_TRANSACTION_ID.toException("Transaction ID is too short");
        }
    }

    /**
     * Ensures that there are no obvious errors within a set of documents
     *
     * @param documents Documents to validate
     * @throws ClientErrorException If error is found within the given documents.
     */
    private void validateDocuments(DocumentRequests documents) throws ClientErrorException {
        if (documents == null) {
            throw (ClientErrorException) ErrorCode.INVALID_DOCUMENT.toException("No documents to be signed", messageSource);
        }

        if (documents.documents == null || documents.documents.size() == 0) {
            throw (ClientErrorException) ErrorCode.INVALID_DOCUMENT.toException("Empty list of documents to be signed", messageSource);
        }

        for (Object object : documents.documents) {
            if (object instanceof DocumentSigningRequest) {
                DocumentSigningRequest document = (DocumentSigningRequest) object;
                if (document.name == null || document.name.length() == 0) {
                    throw (ClientErrorException) ErrorCode.INVALID_DOCUMENT.toException("Missing document name", messageSource);
                }

                if (document.data == null) {
                    throw (ClientErrorException) ErrorCode.INVALID_DOCUMENT.toException("Missing data for document (" + document.getName() + ")", messageSource);
                }

                if (document.type == null || document.type.length() == 0) {
                    throw (ClientErrorException) ErrorCode.INVALID_MIMETYPE.toException("Missing document type for document (" + document.getName() + ")", messageSource);
                }

                if (MimeType.getFileExtension(document.name) != null && !MimeType.fromFileName(document.name).getMimeTypeString().equals(document.type)) {
                    throw (ClientErrorException) ErrorCode.INVALID_MIMETYPE.toException("Invalid type (" + document.getType() + ") for document name (" + document.getName() + "). " + MimeType.fromFileName(document.getName()).getMimeTypeString() + " was exptected.", messageSource);
                }
            } else if (object instanceof DocumentRef) {
                throw (ClientErrorException) ErrorCode.UNSUPPORTED_OPERATION.toException("Document references are not supported", messageSource);
            }
        }
    }

    /**
     * Ensures that there are no obvious errors in a profile.
     *
     * @param profile Profile to validate.
     * @throws ClientErrorException If errors are found within the given profile.
     */
    private void validateProfile(SupportAPIProfile profile) throws ClientErrorException {
        if (profile == null) {
            throw (ClientErrorException) ErrorCode.INVALID_PROFILE.toException("Profile missing (null)");
        }

        if (profile.getRequestedCertAttributes() == null || profile.getRequestedCertAttributes().isEmpty()) {
            throw (ClientErrorException) ErrorCode.INVALID_PROFILE.toException("Profile must contain at least one requested cert attribute");
        }

        if (profile.getRelatedProfile() == null || profile.getRelatedProfile().isEmpty()) {
            throw (ClientErrorException) ErrorCode.INVALID_PROFILE.toException("Related profile name in profile is empty");
        }
    }

    /**
     * Validates a consumer URL against configuration.
     *
     * @param consumerURL URL to validate
     * @param config      Configuration to validate against
     * @return true if consumer URL is valid and authorized
     * @throws ServerErrorException If consumer URL is not authorized to use
     */
    private boolean validateConsumerURL(String consumerURL, SupportAPIProfile config) throws ServerErrorException {
        boolean authorized = false;
        if (config.getAuthorizedConsumerURLs() != null) {
            for (String url : config.getAuthorizedConsumerURLs()) {
                if (consumerURL.startsWith(url)) {
                    authorized = true;
                }
            }
        } else {
            log.warn("No authorized consumer URLs specified in configuration");
        }

        if (!authorized) {
            throw (ServerErrorException) ErrorCode.INVALID_CONFIGURATION.toException("Unauthorized consumer URL: " + consumerURL + ".");
        }

        return authorized;
    }

    private void validateAuthenticationServiceId(String authenticationServiceId, SupportAPIProfile config) throws ClientErrorException {
        boolean validated = false;

        if (config != null) {
            Map<String, Map<String, Object>> trustedAuthenticationServices = config.getTrustedAuthenticationServices();
            if (trustedAuthenticationServices != null) {
                for (Map map : config.getTrustedAuthenticationServices().values()) {
                    if (map.get("entityId") != null && map.get("entityId").equals(authenticationServiceId)) {
                        validated = true;
                    }
                }
            } else {
                log.warn("No trusted authentication services are specified in configuration.");
            }
        }

        if (!validated) {
            throw (ClientErrorException) ErrorCode.UNAUTHORIZED_AUTH_SERVICE.toException("Unauthorized authentication service (" + authenticationServiceId + ")", messageSource);
        }
    }

    /**
     * Builder class to use when building a SupportServiceAPI instance.
     */
    public static class Builder {
        SupportAPIConfiguration config;

        /**
         * Create new TransactionSigner builder
         */
        public Builder() {
            config = new SupportAPIConfiguration();
        }

        /**
         * Specify a custom message source to use when resolving error messages.
         *
         * @param messageSource Message source to use.
         * @return Updated builder.
         */
        public Builder messageSource(MessageSource messageSource) {
            config.setMessageSource(messageSource);
            return this;
        }

        /**
         * Specify a message security provider to use when signing requests and
         * when verifying responses from central system.
         *
         * @param messageSecurityProvider Message security provider to use.
         * @return Updated builder
         */
        public Builder messageSecurityProvider(MessageSecurityProvider messageSecurityProvider) {
            config.setMessageSecurityProvider(messageSecurityProvider);
            return this;
        }

        /**
         * Specify cache provider to use for temporary storage.
         *
         * @param cacheProvider Cache provider to use.
         * @return Updated builder.
         */
        public Builder cacheProvider(CacheProvider cacheProvider) {
            config.setCacheProvider(cacheProvider);
            return this;
        }

        /**
         * Specify certificate source for trusted certificates that are
         * used during validation of documents.
         *
         * @param certificateSource Trusted certificate source.
         * @return Updated builder.
         */
        public Builder trustedCertificateSource(CertificateSource certificateSource) {
            config.setTrustedCertificateSource(certificateSource);
            return this;
        }

        /**
         * Specify timestamp source to use.
         *
         * @param tspSource Timestamp source.
         * @return Updated builder.
         */
        public Builder timeStampSource(TSPSource tspSource) {
            config.setTspSource(tspSource);
            return this;
        }

        /**
         * Specify certificate verifier to use when verifying certificates.
         * If not specified the default verifier will be used.
         *
         * @param certificateVerifier Certificate verifier to use.
         * @return Updated builder.
         */
        public Builder certificateVerifier(CertificateVerifier certificateVerifier) {
            config.setCertificateVerifier(certificateVerifier);
            return this;
        }

        /**
         * Specify proxy settings to use during document validation when fetching
         * revocation data.
         *
         * @param host Proxy host
         * @param port Proxy port
         * @return Updated builder.
         */
        public Builder validationProxy(String host, int port) {
            return validationProxy(host, port, null, null, null);
        }

        /**
         * Specify proxy settings to use during document validation when fetching
         * revocation data.
         *
         * @param host          Proxy host
         * @param port          Proxy port
         * @param excludedHosts List of excluded hosts.
         * @return Updated builder.
         */
        public Builder validationProxy(String host, int port, List<String> excludedHosts) {
            return validationProxy(host, port, null, null, excludedHosts);
        }

        /**
         * Specify proxy settings to use during document validation when fetching
         * revocation data.
         *
         * @param host     Proxy host
         * @param port     Proxy port
         * @param user     Proxy username
         * @param password Proxy Password
         * @return Updated builder.
         */
        public Builder validationProxy(String host, int port, String user, String password) {
            return validationProxy(host, port, user, password, null);
        }

        /**
         * Specify proxy settings to use during document validation when fetching
         * revocation data.
         *
         * @param host          Proxy host
         * @param port          Proxy port
         * @param user          Proxy username
         * @param password      Proxy Password
         * @param excludedHosts List of excluded hosts.
         * @return Updated builder.
         */
        public Builder validationProxy(String host, int port, String user, String password, List<String> excludedHosts) {
            ProxyConfig proxyConfig = new ProxyConfig();
            ProxyProperties proxyProperties = new ProxyProperties();
            proxyProperties.setHost(host);
            proxyProperties.setPort(port);

            if (user != null) {
                proxyProperties.setUser(user);
            }

            if (password != null) {
                proxyProperties.setPassword(password);
            }

            if (excludedHosts != null) {
                proxyProperties.setExcludedHosts(excludedHosts);
            }
            proxyConfig.setHttpProperties(proxyProperties);
            proxyConfig.setHttpsProperties(proxyProperties);
            config.setValidationProxyConfig(proxyConfig);

            return this;
        }

        /**
         * Path to directory containing validation policy files.
         * This can a path on the file system of the classpath. If this
         * is not specified the profile validation policy setting needs to
         * contain the full path to the policy file.
         *
         * @param validationPolicyDirectory Path to directory containing validation policy files.
         * @return Updated builder.
         */
        public Builder validationPolicyDirectory(String validationPolicyDirectory) {
            config.setValidationPolicyDirectory(validationPolicyDirectory);
            return this;
        }

        /**
         * Set expiration time in milliseconds of cache used during
         * validation to store revocation data.
         *
         * @param expirationTimeMS Expiration time in milliseconds.
         * @return Updated builder.
         */
        public Builder validationCacheExpirationTimeMS(long expirationTimeMS) {
            config.setValidationCacheExpirationTimeMS(expirationTimeMS);
            return this;
        }

        /**
         * Specify if simple validation report should be generated or not.
         * If false the validation report will be detailed.
         *
         * @param simpleReport If simple validation report should be used.
         * @return Updated builder.
         */
        public Builder simpleValidationReport(boolean simpleReport) {
            config.setUseSimpleValidationReport(simpleReport);
            return this;
        }

        /**
         * Add list of recipient certificates to use when generating encrypted sign messages.
         *
         * @param authenticationServiceId Authentication service to add recipient for.
         * @param recipients              Recipients of encrypted sign messages.
         * @return Updated builder.
         */
        public Builder addSignMessageRecipients(String authenticationServiceId, List<X509Certificate> recipients) {
            if (!config.getEncryptedSignMessageRecipients().containsKey(authenticationServiceId)) {
                config.getEncryptedSignMessageRecipients().put(authenticationServiceId, new ArrayList<>());
            }
            config.getEncryptedSignMessageRecipients().get(authenticationServiceId).addAll(recipients);
            return this;
        }

        /**
         * Add recipient certificate to use when generating encrypted sign messages.
         *
         * @param authenticationServiceId Authentication service to add recipients for.
         * @param recipient               Recipient of encrypted sign messages.
         * @return Updated builder.
         */
        public Builder addSignMessageRecipient(String authenticationServiceId, X509Certificate recipient) {
            if (!config.getEncryptedSignMessageRecipients().containsKey(authenticationServiceId)) {
                config.getEncryptedSignMessageRecipients().put(authenticationServiceId, new ArrayList<>());
            }
            config.getEncryptedSignMessageRecipients().get(authenticationServiceId).add(recipient);
            return this;
        }

        /**
         * Add mapping between authentication context and level of assurance.
         * Ex. name = softwarePKI
         * context = urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI
         * loa = http://id.elegnamnden.se/loa/1.0/loa3
         *
         * @param name    Display name of mapping.
         * @param context Authentication context identifier.
         * @param loa     Level of assurance identifier.
         * @return Updated builder.
         */
        public Builder addAuthContextMapping(String name, String context, String loa) {
            Map<String, Map> mappings = config.getAuthContextMappings();
            if (mappings == null) {
                mappings = new HashMap<>();
            }
            Map<String, String> entry = new HashMap<>();
            entry.put("context", context);
            entry.put("loa", loa);
            mappings.put(name, entry);

            config.setAuthContextMappings(mappings);
            return this;
        }

        /**
         * Build the Support Service API.
         *
         * @return V2SupportServiceAPI instance based on builder settings.
         */
        public SupportServiceAPI build() throws SupportServiceLibraryException {
            if (config.getAuthContextMappings() == null) {
                log.info("Using default authentication context mappings.");
                addAuthContextMapping("passwordProtectedTransport", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", "http://id.elegnamnden.se/loa/1.0/loa2");
                addAuthContextMapping("softwarePKI", "urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI", "http://id.elegnamnden.se/loa/1.0/loa3");
                addAuthContextMapping("mobileTwoFactorContract", "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract", "http://id.elegnamnden.se/loa/1.0/loa3");
                addAuthContextMapping("smartcardPKI", "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI", "http://id.elegnamnden.se/loa/1.0/loa4");
            }

            return new V2SupportServiceAPI(config);
        }
    }
}
