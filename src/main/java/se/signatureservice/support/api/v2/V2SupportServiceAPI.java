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
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.apache.commons.lang3.EnumUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.encoders.Base64;
import org.certificateservices.messages.ContextMessageSecurityProvider;
import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.csmessages.manager.MessageSecurityProviderManager;
import org.certificateservices.messages.saml2.assertion.jaxb.*;
import org.certificateservices.messages.sweeid2.dssextenstions1_1.AdESType;
import org.certificateservices.messages.sweeid2.dssextenstions1_1.SigType;
import org.certificateservices.messages.sweeid2.dssextenstions1_1.SignMessageMimeType;
import org.certificateservices.messages.sweeid2.dssextenstions1_1.SweEID2DSSExtensionsMessageParser;
import org.certificateservices.messages.sweeid2.dssextenstions1_1.jaxb.*;
import org.certificateservices.messages.utils.DefaultSystemTime;
import org.certificateservices.messages.utils.SystemTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import se.signatureservice.support.api.AvailableSignatureAttributes;
import se.signatureservice.support.api.ErrorCode;
import se.signatureservice.support.api.SupportServiceAPI;
import se.signatureservice.support.common.InternalErrorException;
import se.signatureservice.support.common.InvalidArgumentException;
import se.signatureservice.support.common.cache.CacheProvider;
import se.signatureservice.support.common.cache.DummyCacheProvider;
import se.signatureservice.support.common.cache.MetaData;
import se.signatureservice.support.common.keygen.SignAlgorithm;
import se.signatureservice.support.models.PreparedSignatureInfo;
import se.signatureservice.support.models.TransactionState;
import se.signatureservice.support.system.Constants;
import se.signatureservice.support.system.SupportAPIConfiguration;
import se.signatureservice.support.system.SupportConfiguration;
import se.signatureservice.support.utils.DSSLibraryUtils;
import se.signatureservice.support.utils.SupportLibraryUtils;

import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.JAXBElement;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.awt.*;
import java.io.*;
import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;

import static se.signatureservice.support.api.AvailableSignatureAttributes.*;

/**
 * Implementation of Support Service API version 2.
 *
 * @author Tobias Agerberg
 */
public class V2SupportServiceAPI implements SupportServiceAPI {
    private static final Logger log = LoggerFactory.getLogger(V2SupportServiceAPI.class);
    private static DocumentBuilderFactory documentBuilderFactory;

    private static final String NS_ETSI_1_3_2 = "http://uri.etsi.org/01903/v1.3.2#";
    private static final String NS_W3_XMLNS = "http://www.w3.org/2000/xmlns/";
    private static final String NS_W3_XMLDSIG = "http://www.w3.org/2000/09/xmldsig#";
    private static final String NS_ETSI_1_3_2_SIGNED_PROPERTIES = "http://uri.etsi.org/01903#SignedProperties";

    private static final String XADES_PREFIX = "xades:";
    private static final String XADES_SIGNED_PROPERTIES = "SignedProperties";
    private static final String XADES_SIGNED_SIGNATURE_PROPERTIES = "SignedSignatureProperties";
    private static final String XADES_SIGNING_TIME = "SigningTime";
    private static final String XADES_SIGNING_CERTIFICATE_V2 = "SigningCertificateV2";
    private static final String XADES_CERT = "Cert";
    private static final String XADES_CERT_DIGEST = "CertDigest";
    private static final String XADES_ISSUER_SERIAL_V2 = "IssuerSerialV2";
    private static final String XADES_SIGNED_DATA_OBJECT_PROPERTIES = "SignedDataObjectProperties";
    private static final String XADES_DATA_OBJECT_FORMAT = "DataObjectFormat";
    private static final String XADES_MIME_TYPE = "MimeType";
    private static final String XADES_QUALIFYING_PROPERTIES = "QualifyingProperties";

    private static final String DS_PREFIX = "ds:";
    private static final String DS_DIGESTMETHOD = "DigestMethod";
    private static final String DS_DIGESTVALUE = "DigestValue";
    private static final String DS_OBJECT = "Object";
    private static final String DS_CANONICALIZATIONMETHOD = "CanonicalizationMethod";
    private static final String DS_REFERENCE = "Reference";
    private static final String DS_TRANSFORMS = "Transforms";
    private static final String DS_TRANSFORM = "Transform";

    private static final String XMLNS_DS = "xmlns:ds";
    private static final String XMLNS_XADES = "xmlns:xades";

    private static final String XML_ATTRIBUTE_ID = "Id";
    private static final String XML_ATTRIBUTE_ALGORITHM = "Algorithm";
    private static final String XML_ATTRIBUTE_OBJECT_REFERENCE = "ObjectReference";
    private static final String XML_ATTRIBUTE_TARGET = "Target";
    private static final String XML_ATTRIBUTE_TYPE = "Type";
    private static final String XML_ATTRIBUTE_URI = "URI";
    private static final String XML_MIMETYPE = "text/xml";
    private static final String DSS_CERTIFICATETOKEN_XMLID_PREFIX = "C-";

    private XAdESService xAdESService;
    private PAdESService pAdESService;
    private CAdESService cAdESService;
    private Map<String, OnlineTSPSource> onlineTSPSources;

    private final SupportAPIConfiguration apiConfig;
    private final MessageSource messageSource;
    private final CacheProvider cacheProvider;
    private final Integer transactionTimeToLive = Constants.DEFAULT_TRANSACTION_TTL;

    private SweEID2DSSExtensionsMessageParser sweEID2DSSExtensionsMessageParser;
    private org.certificateservices.messages.sweeid2.dssextenstions1_1.jaxb.ObjectFactory sweEid2ObjectFactory;
    private org.certificateservices.messages.saml2.assertion.jaxb.ObjectFactory saml2ObjectFactory;
    private DatatypeFactory datatypeFactory;
    private SystemTime systemTime;

    /**
     * Create an instance of the support service library.
     *
     * @param apiConfig API configuration.
     */
    private V2SupportServiceAPI(SupportAPIConfiguration apiConfig){
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
            sweEID2DSSExtensionsMessageParser.init(apiConfig.getMessageSecurityProvider(), null);
        } catch(MessageProcessingException e){
            log.error("Failed to initialize message security provider", e);
        }

        xAdESService = new XAdESService(new CommonCertificateVerifier());
        pAdESService = new PAdESService(new CommonCertificateVerifier());
        cAdESService = new CAdESService(new CommonCertificateVerifier());

        onlineTSPSources = new HashMap<>();
    }

    /**
     * Generate signature request info that contains the signature request
     * along with the transaction state that needs to be persisted and supplied
     * to processSignResponse in order to obtain the final signed document(s).
     *
     * @param profileConfig Profile configuration containing various settings to control how the signature request is generated.
     * @param documents Documents to generate sign request for.
     * @param transactionId Transaction ID to use or null to let the library generate one automatically.
     * @param signMessage Signature message to include in the request or null if no signature message should be used.
     * @param user Information about the signatory.
     * @param authenticationServiceId Authentication service (identity provider) to use when signing the document.
     * @param consumerURL Return URL that the user should be redirected to in the end of the signature flow.
     * @param signatureAttributes Optional attributes to use.
     * @return SignRequestInfo instance that contains the XML signature request along with the transaction state.
     * @throws ClientErrorException If an error occurred when generating the signature request due to client supplied data.
     * @throws ServerErrorException If an internal error occurred when generating the signature request.
     */
    @Override
    public PreparedSignatureInfo prepareSignature(SupportConfiguration profileConfig, DocumentRequests documents, String transactionId, String signMessage, User user, String authenticationServiceId, String consumerURL, List<Attribute> signatureAttributes) throws ClientErrorException, ServerErrorException {
        long operationStart = System.currentTimeMillis();
        PreparedSignatureInfo signRequestInfo = null;
        try {
            if (transactionId == null) {
                transactionId = SupportLibraryUtils.generateTransactionId();
            } else {
                validateTransactionId(transactionId);
            }

            validateDocuments(documents);
            validateAuthenticationServiceId(authenticationServiceId, profileConfig);

            ContextMessageSecurityProvider.Context context  = new ContextMessageSecurityProvider.Context(se.signatureservice.support.common.Constants.CONTEXT_USAGE_SIGNREQUEST, profileConfig.getRelatedProfile());
            PreparedSignatureResponse preparedSignature = new PreparedSignatureResponse();
            preparedSignature.setProfile(profileConfig.getRelatedProfile());
            preparedSignature.setActionURL(profileConfig.getSignServiceRequestURL());
            preparedSignature.setTransactionId(transactionId);
            preparedSignature.setSignRequest(generateSignRequest(context, transactionId, documents, signMessage, user, authenticationServiceId, consumerURL, profileConfig, signatureAttributes));

            TransactionState transactionState = new TransactionState();
            transactionState.setProfile(profileConfig.getRelatedProfile());
            transactionState.setTransactionId(transactionId);
            transactionState.setSignMessage(signMessage);
            transactionState.setAuthenticationServiceId(authenticationServiceId);
            transactionState.setUser(user);
            transactionState.setDocuments(documents);
            transactionState.setTransactionStart(operationStart);
            transactionState.setCompleted(false);

            signRequestInfo = new PreparedSignatureInfo(preparedSignature, serializeTransactionState(transactionState));
        } catch(IOException | MessageContentException | MessageProcessingException | BaseAPIException | InvalidArgumentException | InternalErrorException | ClassNotFoundException | ParserConfigurationException | SAXException | InvalidCanonicalizerException | CanonicalizationException | CertificateEncodingException | NoSuchAlgorithmException | TransformerException e){
            throw (ServerErrorException)ErrorCode.INTERNAL_ERROR.toException("Failed to generate sign request: " + e.getMessage());
        }

        return signRequestInfo;
    }

    /**
     * Process a signature response along with the transaction state in order to compile
     * a complete signature response containing signed document(s).
     *
     * @param signResponse     Signature response to process.
     * @param transactionState Related transaction state given by the initial call to generateSignRequest.
     * @return CompleteSignatureResponse that contains the signed document(s).
     * @throws ClientErrorException If an error occurred when generating the signature request due to client supplied data.
     * @throws ServerErrorException If an internal error occurred when generating the signature request.
     */
    @Override
    public CompleteSignatureResponse completeSignature(String signResponse, byte[] transactionState) throws ClientErrorException, ServerErrorException {

        return null;
    }

    /**
     * Serialize transaction state object into byte array.
     *
     * @param transactionState Transaction state object to serialize.
     * @return Serialized transactioon state as byte array.
     * @throws IOException If serialization failed.
     */
    private byte[] serializeTransactionState(TransactionState transactionState) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(transactionState);
        return baos.toByteArray();
    }

    /**
     * Generate Base64 encoded SignRequest according to Swedish eID framework.
     *
     * @param context Security provider context
     * @param transactionId Transaction ID to use
     * @param documents Documents to be signed
     * @param signMessage Message to show during signing process or null if no message should be shown
     * @param user User signatory information
     * @param authenticationServiceId identity provider to use during signature process
     * @param consumerURL URL where the user will be sent when signature process is completed
     * @param config Configuration to use when generating request
     * @return Marshalled SignRequest XML-document based on given parameters
     */
    private synchronized String generateSignRequest(ContextMessageSecurityProvider.Context context, String transactionId, DocumentRequests documents,
                               String signMessage, User user, String authenticationServiceId, String consumerURL,
                               SupportConfiguration config, List<Attribute> signatureAttributes) throws IOException, MessageContentException, MessageProcessingException, BaseAPIException, InvalidArgumentException, InternalErrorException, ClassNotFoundException, ParserConfigurationException, SAXException, InvalidCanonicalizerException, CanonicalizationException, CertificateEncodingException, NoSuchAlgorithmException, TransformerException {

        GregorianCalendar requestTime = new GregorianCalendar();
        requestTime.setTime(new Date());
        SignRequestExtensionType signRequestExtensionType = sweEid2ObjectFactory.createSignRequestExtensionType();
        if(StringUtils.isNoneEmpty(signMessage)){
            signRequestExtensionType.setSignMessage(generateSignMessage(context, signMessage, authenticationServiceId, config));
        }


        signRequestExtensionType.setVersion(config.getSignRequestExtensionVersion());
        signRequestExtensionType.setConditions(generateConditions(requestTime, consumerURL, config));
        signRequestExtensionType.setSigner(generateSigner(user, authenticationServiceId, config));
        signRequestExtensionType.setRequestTime(datatypeFactory.newXMLGregorianCalendar(requestTime));
        signRequestExtensionType.setIdentityProvider(createNameIDType(authenticationServiceId,"urn:oasis:names:tc:SAML:2.0:nameid-format:entity"));
        signRequestExtensionType.setSignService(createNameIDType(config.getSignServiceId(), "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"));
        signRequestExtensionType.setCertRequestProperties(sweEid2ObjectFactory.createCertRequestPropertiesType());
        signRequestExtensionType.getCertRequestProperties().getAuthnContextClassRef().addAll(getAuthnContextClassRefs(authenticationServiceId, config));
        signRequestExtensionType.setSignRequester(createNameIDType(config.getSignRequester(), "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"));
        signRequestExtensionType.getCertRequestProperties().setCertType(config.getCertificateType());
        signRequestExtensionType.setRequestedSignatureAlgorithm(SignatureAlgorithm.forJAVA(config.getSignatureAlgorithm()).getUri());
        signRequestExtensionType.getCertRequestProperties().setRequestedCertAttributes(sweEid2ObjectFactory.createRequestedAttributesType());

        if(config.isEnableAuthnProfile()){
            signRequestExtensionType.setAuthnProfile(config.getRelatedProfile());
        }

        if(config.getRequestedCertAttributes() != null) {
            for(Map.Entry<String, Map> entry : config.getRequestedCertAttributes().entrySet()){
                signRequestExtensionType.getCertRequestProperties().getRequestedCertAttributes().getRequestedCertAttribute().add(
                        generateRequestedAttribute(entry.getKey(), entry.getValue(), config.getRelatedProfile())
                );
            }
        }

        JAXBElement<SignRequestExtensionType> signRequestExtension = sweEid2ObjectFactory.createSignRequestExtension(signRequestExtensionType);
        SignTasksType signTasksType = sweEid2ObjectFactory.createSignTasksType();

        for(Object object : documents.documents){
            if(object instanceof DocumentSigningRequest){
                DocumentSigningRequest documentSigningRequest = (DocumentSigningRequest)object;
                if(documentSigningRequest.referenceId == null){
                    documentSigningRequest.referenceId = SupportLibraryUtils.generateReferenceId();
                }
                signTasksType.getSignTaskData().add(generateSignTask(documentSigningRequest, transactionId, getSigningId(user, config), config, signatureAttributes));
            } else if(object instanceof DocumentRef) {
                // TODO: Implement support for signing document by reference
            }
        }

        JAXBElement<SignTasksType> signTasks = sweEid2ObjectFactory.createSignTasks(signTasksType);
        byte[] signRequest = sweEID2DSSExtensionsMessageParser.genSignRequest(context, transactionId, se.signatureservice.support.common.Constants.SWE_EID_DSS_PROFILE, signRequestExtension, signTasks, true);
        return new String(Base64.encode(signRequest), "UTF-8");
    }

    private NameIDType createNameIDType(String value, String format){
        NameIDType nameIDType = new NameIDType();
        nameIDType.setValue(value);
        nameIDType.setFormat(format);
        return nameIDType;
    }

    /**
     * Get signing id to use for signature
     *
     * @param user User performing the signature
     * @param config Configuration to use
     * @return Signing id (displayname) to use for signature.
     */
    protected String getSigningId(User user, SupportConfiguration config) {
        String signingId = user.getUserId();
        if(config.getUserDisplayNameAttribute() != null && user.getUserAttributes() != null) {
            Attribute userDisplayNameAttribute = null;
            for(Attribute attribute : user.getUserAttributes()){
                if(attribute.getKey().equals(config.getUserDisplayNameAttribute())){
                    userDisplayNameAttribute = attribute;
                    break;
                }
            }

            if(userDisplayNameAttribute != null) {
                signingId = userDisplayNameAttribute.getValue();
            }
        }
        return signingId;
    }

    /**
     * Generate sign task for a given document
     *
     * @param document DocumentSigningRequest containing document to generate sign task for.
     * @param transactionId Transaction ID for signature flow
     * @param signingId Signing identity (e.g. name) to use when creating signature data-to-be-signed.
     * @param config Configuration to use
     * @return Sign task for given document data.
     */
    private SignTaskDataType generateSignTask(DocumentSigningRequest document, String transactionId, String signingId,
                                              SupportConfiguration config, List<Attribute> signatureAttributes) throws InvalidArgumentException, ClientErrorException, IOException, InternalErrorException, ClassNotFoundException, ServerErrorException, ParserConfigurationException, MessageProcessingException, SAXException, InvalidCanonicalizerException, CanonicalizationException, CertificateEncodingException, NoSuchAlgorithmException, TransformerException {
        SignTaskDataType signTask = sweEid2ObjectFactory.createSignTaskDataType();
        signTask.setSigType(getSigTypeFromMimeType(document.type));
        signTask.setSignTaskId(document.getReferenceId());
        signTask.setToBeSignedBytes(generateToBeSignedBytes(signTask, document, transactionId, signingId, config, signatureAttributes));

        return signTask;
    }

    /**
     * Generate a MappedAttributeType containing a requested attribute used to represent
     * requests for subject attributes in a signer certificate that is associated with the signer
     * of the generated signature as a result of the sign request.
     *
     * Parameters map may contain the following keys (described in the Swedish eID framework, ELN-0609:3.1.1.1)
     *     - samlAttributeName
     *     - certAttributeRef
     *     - certNameType
     *     - required
     *
     * @param friendlyName Name of attribute
     * @param parameters Attribute parameters
     * @param profile the profile name
     * @return MappedAttributeType element based on given parameters
     */
    private MappedAttributeType generateRequestedAttribute(String friendlyName, Map parameters, String profile) throws BaseAPIException {
        MappedAttributeType requestedAttribute;
        try{
            requestedAttribute = new MappedAttributeType();
            requestedAttribute.setCertAttributeRef((String)parameters.get("certAttributeRef"));
            requestedAttribute.setFriendlyName(friendlyName);
            requestedAttribute.setRequired((boolean)parameters.get("required"));
            requestedAttribute.setCertNameType((String)parameters.get("certNameType"));
        } catch(Exception e){
            throw (ClientErrorException)ErrorCode.INVALID_PROFILE.toException("Invalid parameter specified under profile: " + profile + ": " + e.getMessage());
        }

        if(parameters.get("samlAttributeName") instanceof String){
            PreferredSAMLAttributeNameType preferredSAMLAttributeNameType = new PreferredSAMLAttributeNameType();
            preferredSAMLAttributeNameType.setValue((String)parameters.get("samlAttributeName"));
            requestedAttribute.getSamlAttributeName().add(preferredSAMLAttributeNameType);
        } else if(parameters.get("samlAttributeName") instanceof List){
            for(Map samlAttributeNameMap : (List<Map<String,String>>)parameters.get("samlAttributeName")){
                if(samlAttributeNameMap.get("order") != null && !samlAttributeNameMap.get("order").equals("")){
                    Integer order;
                    try{
                        order = Integer.parseInt(samlAttributeNameMap.get("order").toString());
                    } catch(Exception e){
                        throw ErrorCode.INVALID_PROFILE.toException(profile + ".requestedCertAttributes.serialNumber." + samlAttributeNameMap.get("value") + " has no-integer order value.");
                    }
                    if(order < 0){
                        throw ErrorCode.INVALID_PROFILE.toException(profile + ".requestedCertAttributes.serialNumber." + samlAttributeNameMap.get("value") + " has invalid order value. Order must be larger than or equal to 0");
                    }
                    PreferredSAMLAttributeNameType preferredSAMLAttributeNameType = new PreferredSAMLAttributeNameType();
                    preferredSAMLAttributeNameType.setValue((String)samlAttributeNameMap.get("value"));
                    preferredSAMLAttributeNameType.setOrder(order);
                    requestedAttribute.getSamlAttributeName().add(preferredSAMLAttributeNameType);

                } else{
                    PreferredSAMLAttributeNameType preferredSAMLAttributeNameType = new PreferredSAMLAttributeNameType();
                    preferredSAMLAttributeNameType.setValue((String)samlAttributeNameMap.get("value"));
                    requestedAttribute.getSamlAttributeName().add(preferredSAMLAttributeNameType);
                }
            }
        } else{
            throw ErrorCode.INVALID_PROFILE.toException("The samlAttributeName under ${profile}.requestedCertAttributes must be a string or a list of map.");
        }

        return requestedAttribute;
    }

    /**
     * Get TSP source from cache if possible or create new one.
     * @param timeStampServer Timestamp server
     * @return TSP source for given timestamp server.
     */
    private OnlineTSPSource getTspSource(String timeStampServer) {
        OnlineTSPSource tspSource = onlineTSPSources.get(timeStampServer);
        if(tspSource == null){
            tspSource = new OnlineTSPSource(timeStampServer);
            onlineTSPSources.put(timeStampServer, tspSource);
        }
        return tspSource;
    }

    /**
     * Generate data to be signed for a given document and create any needed AdES-object
     *
     * @param signTask Related Signtask that will be updated during the process.
     * @param document DocumentSigningRequest containing document to be signed
     * @param transactionId Transaction ID for signature flow
     * @param signingId Signing identity (e.g. name) to use when creating signature data-to-be-signed.
     * @param config Configuration to use
     * @return Data to be signed for the given document
     */
    private byte[] generateToBeSignedBytes(SignTaskDataType signTask, DocumentSigningRequest document, String transactionId,
                                           String signingId, SupportConfiguration config, List<Attribute> signatureAttributes) throws ClientErrorException, InvalidArgumentException, IOException, InternalErrorException, ClassNotFoundException, ServerErrorException, ParserConfigurationException, MessageProcessingException, SAXException, InvalidCanonicalizerException, CanonicalizationException, CertificateEncodingException, NoSuchAlgorithmException, TransformerException {
        SigType sigType = SigType.valueOf(getSigTypeFromMimeType(document.getType()));
        DSSDocument dssDocument = DSSLibraryUtils.createDSSDocument(document);
        AbstractSignatureParameters dssParameters = getSignatureParameters(sigType, config);

        switch(sigType) {
            case XML:
                if(!config.getXadesSignatureLevel().equals(SignatureLevel.XAdES_BASELINE_B.toString()) && config.getTimeStampServer() != null){
                    xAdESService.setTspSource(onlineTSPSources.get(config.getTimeStampServer()));
                }
                signTask.setToBeSignedBytes(xAdESService.getDataToSign(dssDocument, (XAdESSignatureParameters)dssParameters).getBytes());
                break;
            case PDF:
                if(!config.getPadesSignatureLevel().equals(SignatureLevel.PAdES_BASELINE_B.toString()) && config.getTimeStampServer() != null){
                    pAdESService.setTspSource(getTspSource(config.getTimeStampServer()));
                }
                PAdESSignatureParameters pAdESParameters = (PAdESSignatureParameters)dssParameters;
                pAdESParameters.setSignerName(signingId);

                boolean validAttributes = validateVisibleSignatureAttributes(signatureAttributes);
                if (config.isEnableVisibleSignature()) {
                    if (validAttributes) {
                        setVisibleSignature(config, pAdESParameters, signingId, transactionId, signatureAttributes);
                    } else {
                        log.warn("Visible signatures are enabled in configuration (enableVisibleSignature) but required signature attributes are missing. The following attributes are required: " +
                                AvailableSignatureAttributes.VISIBLE_SIGNATURE_POSITION_X + ", " +
                                AvailableSignatureAttributes.VISIBLE_SIGNATURE_POSITION_Y + ", " +
                                AvailableSignatureAttributes.VISIBLE_SIGNATURE_WIDTH + ", " +
                                AvailableSignatureAttributes.VISIBLE_SIGNATURE_HEIGHT);
                    }
                } else if (validAttributes) {
                    log.warn("Visible signature attributes are requested, but 'enableVisibleSignature' is disabled in the configuration.");
                }

                pAdESService.setPdfObjFactory(new PdfBoxDefaultObjectFactory());
                signTask.setToBeSignedBytes(pAdESService.getDataToSign(dssDocument, pAdESParameters).getBytes());
                break;
            case CMS:
                if(!config.getCadesSignatureLevel().equals(SignatureLevel.CAdES_BASELINE_B.toString()) && config.getTimeStampServer() != null){
                    cAdESService.setTspSource(onlineTSPSources.get(config.getTimeStampServer()));
                }
                signTask.setToBeSignedBytes(cAdESService.getDataToSign(dssDocument, (CAdESSignatureParameters)dssParameters).getBytes());
                break;
            default:
                break;
        }

        // Generate Base AdES-object if needed
        AdESType adESType = getAdESType(sigType, config);
        signTask.setAdESType(adESType.name());

        // XAdES is the only signature type that has a separate AdES-object.
        if(adESType == AdESType.BES && sigType == SigType.XML){
            createNewXadesObject(signTask, config.getSignatureAlgorithm(), null, dssParameters.bLevel().getSigningDate());
        }

        // Store signing time in cache
        TransactionState transactionState = fetchTransactionState(transactionId);
        if(transactionState == null){
            transactionState = new TransactionState();
        }
        transactionState.getSigningTime().put(document.referenceId, dssParameters.bLevel().getSigningDate());
        storeTransactionState(transactionId, transactionState);

        log.debug("Generated ToBeSignedBytes (" + sigType.name() + ") = " + new String(Base64.encode(signTask.getToBeSignedBytes())));
        return signTask.getToBeSignedBytes();
    }

    protected void setVisibleSignature(SupportConfiguration config, PAdESSignatureParameters parameters, String signerName,
                                       String transactionId, List<Attribute> signatureAttributes) throws ServerErrorException {
        try {
            SignatureImageParameters imageParameters = getImageParameters(transactionId, signatureAttributes);

            boolean useDefaultImage = false;
            if (config.getVisibleSignatureImage() == "" || config.getVisibleSignatureImage() == null) {
                useDefaultImage = true;
            } else {
                File file = new File(config.getVisibleSignatureImage());
                if (!file.exists() || !file.isFile() || !file.canRead()) {
                    useDefaultImage = true;
                    log.debug("The provided image path is not valid and use the default file. Check if the provided path points to an existing file and it has read permission.");
                }
            }

            if (useDefaultImage) {
                imageParameters.setImage(new InMemoryDocument(this.getClass().getResourceAsStream(Constants.DEFAULT_IMAGE_PATH), "CGI_Logon.png"));
            } else {
                imageParameters.setImage(new InMemoryDocument(new FileInputStream(new File(config.getVisibleSignatureImage())), "customizedImage.png"));
            }

            SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
            if(cacheProvider.get(transactionId, Constants.VISIBLE_SIGNATURE_REQUEST_TIME) == null){
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                cacheProvider.set(transactionId, Constants.VISIBLE_SIGNATURE_REQUEST_TIME, sdf.format(new Date()));
            }
            textParameters.setText("Document Digital Signed\nSigner: ${signerName} \nTime: ${cacheService.get(transactionId, VISIBLE_SIGNATURE_REQUEST_TIME)}");
            textParameters.setSignerTextPosition(SignerTextPosition.RIGHT);
            textParameters.setBackgroundColor(Color.WHITE);
            textParameters.setTextColor(Color.BLACK);
            imageParameters.setTextParameters(textParameters);
            parameters.setImageParameters(imageParameters);
        }catch(Exception e){
            log.error("Can't set visible signature parameters for the PAdESSignatureParameters: " + e.getMessage());
            throw (ServerErrorException)ErrorCode.SIGN_REQUEST_FAILED.toException(e, messageSource);
        }
    }

    /**
     * Store transaction state in cache service with TTL from configuration or default.
     *
     * @param transactionId Transaction ID that will be used as cache key
     * @param state Transaction state to save for the given relay state
     * @return Stored state
     */
    protected TransactionState storeTransactionState(String transactionId, TransactionState state) throws IOException, InvalidArgumentException, InternalErrorException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(state);
        MetaData metaData = new MetaData();
        metaData.setTimeToLive(transactionTimeToLive);
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
        if(serializedState != null) {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedState)){
                protected Class<?> resolveClass(ObjectStreamClass objectStreamClass) throws IOException, ClassNotFoundException {
                    return Class.forName(objectStreamClass.getName(), true, V2SupportServiceAPI.class.getClassLoader());
                }
            };
            return (TransactionState)ois.readObject();
        }

        return null;
    }

    /**
     * Get AdESType for a given signature type based on a given configuration.
     * @param sigType Signature type to get AdESType for
     * @param config Configuration that is used
     * @return The AdESType to use for a given signature type and configuration.
     */
    private AdESType getAdESType(SigType sigType, SupportConfiguration config){
        AdESType adESType = AdESType.None;

        switch(sigType) {
            case XML:
                if(!config.getXadesSignatureLevel().equals(SignatureLevel.XML_NOT_ETSI.toString())){
                    adESType = AdESType.BES;
                }
                break;
            case PDF:
                if(!config.getPadesSignatureLevel().equals(SignatureLevel.PDF_NOT_ETSI.toString())){
                    adESType = AdESType.BES;
                }
                break;
            case CMS:
                if(!config.getCadesSignatureLevel().equals(SignatureLevel.CMS_NOT_ETSI.toString())){
                    adESType = AdESType.BES;
                }
                break;
            default:
                break;
        }
        return adESType;
    }

    /**
     * Get signature parameters to use when creating request, depending on signature type and configuration
     *
     * @param sigType Signature type to get parameters for.
     * @param config Configuration to use.
     * @return Signature parameters to use when creating request
     */
    protected AbstractSignatureParameters getSignatureParameters(SigType sigType, SupportConfiguration config) throws ClientErrorException {
        AbstractSignatureParameters parameters;
        switch(sigType){
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
                pp.setSignaturePackaging(SignaturePackaging.valueOf(config.getPadesSignaturePacking()));
                parameters = pp;
                break;
            default:
                throw (ClientErrorException)ErrorCode.UNSUPPORTED_SIGNATURE_TYPE.toException("Signature type not supported (" + sigType.name() + ")");
        }

        parameters.setGenerateTBSWithoutCertificate(true);
        parameters.bLevel().setSigningDate(DateUtils.round(new Date(), Calendar.SECOND));
        parameters.setEncryptionAlgorithm(SignatureAlgorithm.forJAVA(config.getSignatureAlgorithm()).getEncryptionAlgorithm());
        parameters.setDigestAlgorithm(SignatureAlgorithm.forJAVA(config.getSignatureAlgorithm()).getDigestAlgorithm());

        return parameters;
    }

    private SignatureImageParameters getImageParameters(String transactionId, List<Attribute> signatureAttributes) throws ClientErrorException {
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        try {
            if(signatureAttributes == null){
                imageParameters.setxAxis(getSignAttributeFloatValue(transactionId, VISIBLE_SIGNATURE_POSITION_X, cacheProvider.get(transactionId, VISIBLE_SIGNATURE_POSITION_X)));
                imageParameters.setyAxis(getSignAttributeFloatValue(transactionId, VISIBLE_SIGNATURE_POSITION_Y, cacheProvider.get(transactionId, VISIBLE_SIGNATURE_POSITION_Y)));
                imageParameters.setWidth(getSignAttributeIntegerValue(transactionId, VISIBLE_SIGNATURE_WIDTH, cacheProvider.get(transactionId, VISIBLE_SIGNATURE_WIDTH)));
                imageParameters.setHeight(getSignAttributeIntegerValue(transactionId, VISIBLE_SIGNATURE_HEIGHT, cacheProvider.get(transactionId, VISIBLE_SIGNATURE_HEIGHT)));
                imageParameters.setPage(getSignAttributeIntegerValue(transactionId, VISIBLE_SIGNATURE_PAGE, cacheProvider.get(transactionId, VISIBLE_SIGNATURE_PAGE)));
            } else if (signatureAttributes.size() != 0) {
                for(Attribute attr : signatureAttributes){
                    if (attr.getKey().equals(VISIBLE_SIGNATURE_POSITION_X)) {
                        imageParameters.setxAxis(getSignAttributeFloatValue(transactionId, attr.getKey(), attr.getValue()));
                    } else if (attr.getKey().equals(VISIBLE_SIGNATURE_POSITION_Y)) {
                        imageParameters.setyAxis(getSignAttributeFloatValue(transactionId, attr.getKey(), attr.getValue()));
                    } else if (attr.getKey().equals(VISIBLE_SIGNATURE_WIDTH)) {
                        imageParameters.setWidth(getSignAttributeIntegerValue(transactionId, attr.getKey(), attr.getValue()));
                    } else if (attr.getKey().equals(VISIBLE_SIGNATURE_HEIGHT)) {
                        imageParameters.setHeight(getSignAttributeIntegerValue(transactionId, attr.getKey(), attr.getValue()));
                    } else if (attr.getKey().equals(VISIBLE_SIGNATURE_PAGE)) {
                        imageParameters.setPage(getSignAttributeIntegerValue(transactionId, attr.getKey(), attr.getValue()));
                    } else {
                        log.info("Ignore attribute: " + attr.getKey() + " for visible signature image settings.");
                    }
                }

                if (imageParameters.getxAxis() == 0) {
                    throw (ClientErrorException)ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException("Make sure attribute: ${VISIBLE_SIGNATURE_POSITION_X} is configured with a value larger than 0.");
                } else if (imageParameters.getyAxis() == 0) {
                    throw (ClientErrorException)ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException("Make sure attribute: ${VISIBLE_SIGNATURE_POSITION_Y} is configured with a value larger than 0.");
                } else if (imageParameters.getWidth() < 180) {
                    throw (ClientErrorException)ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException("Make sure attribute: ${VISIBLE_SIGNATURE_WIDTH} is configured with a value larger than 180. The minimum image size is: 180*40.");
                } else if (imageParameters.getHeight() < 40) {
                    throw (ClientErrorException)ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException("Make sure attribute: ${VISIBLE_SIGNATURE_HEIGHT} is configured with a value larger than 40. The minimum image size is: 180*40.");
                }
            } else {
                throw (ClientErrorException)ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException("No visible signature attribute configured.");
            }
            return imageParameters;
        } catch(Exception e){
            log.error("Can't set visible signature parameters for the PAdESSignatureParameters. Message: " + e.getMessage());
            throw (ClientErrorException)ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException(e, messageSource);
        }
    }

    /**
     * Method to get the float value for the image x/y coordinate parameters
     */
    private float getSignAttributeFloatValue(String transactionId, String attributeName, String attributeValue) throws InvalidParameterException, ClientErrorException, InvalidArgumentException, IOException, InternalErrorException {
        float value;
        if(attributeValue == null || attributeValue.isEmpty()){
            throw (ClientErrorException)ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException("Invalid sign attribute configured. Can't set " + attributeName + " with empty value or null.");
        }
        try {
            value = Float.parseFloat(attributeValue);
        } catch (Exception e) {
            throw (ClientErrorException)ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException("Invalid sign attribute " + attributeName + "=" + attributeValue + " configured. Can't convert " + attributeValue + " to float value.");
        }
        if (value < 0) {
            throw (ClientErrorException)ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException("Invalid sign attribute " + attributeName + "=" + attributeValue + " configured. " + attributeName + " should be larger than 0.");
        }
        cacheProvider.set(transactionId, attributeName, attributeValue);
        return value;
    }

    /**
     * Method to get the integer value for the image page/width/height parameters
     */
    private int getSignAttributeIntegerValue(String transactionId, String attributeName, String attributeValue) throws InvalidParameterException, ClientErrorException, InvalidArgumentException, IOException, InternalErrorException {
        int value;
        if(attributeValue == null || attributeValue.isEmpty()){
            throw (ClientErrorException)ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException("Invalid sign attribute configured. Can't set " + attributeName + " with empty value or null.");
        }
        try {
            value = Integer.parseInt(attributeValue);
        } catch (Exception e) {
            throw (ClientErrorException)ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException("Invalid sign attribute " + attributeName + "=" + attributeValue + " configured. Can't convert " + attributeValue + " to integer.");
        }
        if (value < 1) {
            throw (ClientErrorException)ErrorCode.INVALID_VISIBLE_SIGNATURE_ATTRIBUTE.toException("Invalid sign attribute " + attributeName + "=" + attributeValue + " configured. " + attributeName + " should be equal to or larger than 1.");
        }
        cacheProvider.set(transactionId, attributeName, attributeValue);
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
        for(Attribute a : signatureAttributes){
            attributeKeys.add(a.getKey());
        }

        return attributeKeys.containsAll(requiredAttributeKeys);
    }

    /**
     * Get signature type from a given document mime type.
     * @param mimeType
     * @return Signature type ("XML", "PDF" or "CMS") for given mime type.
     */
    protected String getSigTypeFromMimeType(String mimeType) {
        if(mimeType.equals(MimeType.XML.getMimeTypeString())){
            return SigType.XML.name();
        } else if(mimeType.equals(MimeType.PDF.getMimeTypeString())){
            return SigType.PDF.name();
        }

        return SigType.CMS.name();
    }

    /**
     * Generate SignMessage to be shown to user before signing
     *
     * @param message Message to display
     * @param displayEntity The EntityID of the entity responsible for displaying the sign message to the signer.
     * @return SignMessageType element based on given parameters
     */
    private SignMessageType generateSignMessage(ContextMessageSecurityProvider.Context context, String message, String displayEntity, SupportConfiguration config) throws UnsupportedEncodingException, MessageProcessingException {
        SignMessageType signMessage;
        SignMessageMimeType mimeType;

        if(EnumUtils.isValidEnum(SignMessageMimeType.class, config.getSignMessageMimeType())){
            mimeType = SignMessageMimeType.valueOf(config.getSignMessageMimeType());
        } else {
            log.error("Invalid mimetype for sign messages specified in configuration: " + config.getSignMessageMimeType() + ". Using 'text' as fallback.");
            mimeType = SignMessageMimeType.TEXT;
        }

        if(config.isUseEncryptedSignMessage()){
            List<X509Certificate> signMessageRecipients = apiConfig.getEncryptedSignMessageRecipients().get(displayEntity);
            signMessage = sweEID2DSSExtensionsMessageParser.genSignEncryptedMessage(context, config.isSignMessageMustShow(), displayEntity, mimeType, message.getBytes("UTF-8"), null, signMessageRecipients);
        } else {
            signMessage = sweEID2DSSExtensionsMessageParser.genSignMessage(config.isSignMessageMustShow(), displayEntity, mimeType, message.getBytes("UTF-8"), null);
        }

        return signMessage;
    }

    /**
     * Generate Signer element based on user data
     *
     * @param user User to generate signer element from
     * @return Signer AttributeStatementType element based on given user data
     */
    private AttributeStatementType generateSigner(User user, String authenticationServiceId, SupportConfiguration config) throws ServerErrorException {
        AttributeStatementType attributeStatementType = saml2ObjectFactory.createAttributeStatementType();

        // Add the mandatory userId signer attribute before processing any additional attributes.
        String userIdAttributeName = getUserIdAttributeMapping(authenticationServiceId, config);
        attributeStatementType.getAttributeOrEncryptedAttribute().add(generateSignerAttribute(userIdAttributeName, user.getUserId()));

        // Add any additional signer attributes defined in configuration.
        if(config.getSignerAttributes() != null) {

            for(Map.Entry<String,Map> entry : config.getSignerAttributes().entrySet()){

                Attribute userAttribute = null;
                for(Attribute attribute : user.getUserAttributes()){
                    if(attribute.getKey().equals(entry.getValue().get("userAttributeMapping"))){
                        userAttribute = attribute;
                        break;
                    }
                }

                if(userAttribute == null && (boolean)entry.getValue().get("required")){
                    throw (ServerErrorException)ErrorCode.MISSING_CONFIGURATION.toException("Missing required user attribute, defined in signerAttributes configuration: " + entry.getValue().get("userAttributeMapping"));
                } else if(userAttribute != null){
                    attributeStatementType.getAttributeOrEncryptedAttribute().add(generateSignerAttribute((String)entry.getValue().get("samlAttributeName"), userAttribute.getValue()));
                }
            }
        }

        return attributeStatementType;
    }

    /**
     * Get DocumentBuilderFactory to use when creating new instance of
     * DocumentBuilder. This is shared across threads.
     * @return
     */
    static DocumentBuilderFactory getSignedInfoDocumentBuilderFactory(){
        if(documentBuilderFactory == null){
            documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
        }
        return documentBuilderFactory;
    }

    /**
     * Get document builder in order to build SignedInfo and SignedProperties document.
     * DocumentBuilder is not thread safe so we create a new per thread.
     * @return Document builder
     */
    static DocumentBuilder getSignedInfoDocumentBuilder() throws ParserConfigurationException {
        return getSignedInfoDocumentBuilderFactory().newDocumentBuilder();
    }

    /**
     * Create new XaDES-object from scratch that will be used during the signature process for
     * advanced XML signatures (XAdES).
     * @param signTask Sign task to update with new XAdES-object
     * @param signTransformation Signature transformation that is used.
     * @param signingCertificate Signature certificate that will be used to sign the ToBeSignedBytes
     * @param signingTime Signing time to use or null to use the current system time.
     */
    private void createNewXadesObject(SignTaskDataType signTask, String signTransformation, X509Certificate signingCertificate, Date signingTime) throws MessageProcessingException, IOException, SAXException, ParserConfigurationException, TransformerException, InvalidCanonicalizerException, CertificateEncodingException, NoSuchAlgorithmException, CanonicalizationException {
        SignAlgorithm signAlgorithm = SignAlgorithm.getAlgoByJavaName(signTransformation);
        DocumentBuilder documentBuilder = getSignedInfoDocumentBuilder();
        org.w3c.dom.Document signedInfo = documentBuilder.parse(new ByteArrayInputStream(signTask.getToBeSignedBytes()));

        // We re-use the same canonicalization algorithm so we dont have to
        // handle split-configuration between signservice-support and signservice-backend.
        NodeList nodeList = signedInfo.getElementsByTagNameNS(NS_W3_XMLDSIG, DS_CANONICALIZATIONMETHOD);
        Element canonicalizationMethodElement = nodeList != null ? (Element)signedInfo.getElementsByTagNameNS(NS_W3_XMLDSIG, DS_CANONICALIZATIONMETHOD).item(0) : null;
        String canonicalizationMethod = canonicalizationMethodElement.getAttribute(XML_ATTRIBUTE_ALGORITHM);

        if(signingTime == null){
            signingTime = DateUtils.round(getSystemTime().getSystemTime(), Calendar.SECOND);
        }

        String signedPropertiesId = getSignedPropertiesId(signTask, signingTime, signingCertificate);

        // Create new SignedProperties that includes signing-certificate
        Document document = documentBuilder.newDocument();
        Element object = document.createElementNS(NS_W3_XMLDSIG, DS_PREFIX + DS_OBJECT);
        document.appendChild(object);
        Element qualifyingProperties = document.createElementNS(NS_ETSI_1_3_2, XADES_PREFIX + XADES_QUALIFYING_PROPERTIES);
        qualifyingProperties.setAttribute(XML_ATTRIBUTE_TARGET, "#" + signedPropertiesId);
        object.appendChild(qualifyingProperties);
        Element signedProperties = document.createElementNS(NS_ETSI_1_3_2, XADES_PREFIX + XADES_SIGNED_PROPERTIES);
        signedProperties.setAttributeNS(NS_W3_XMLNS, XMLNS_DS, NS_W3_XMLDSIG);
        signedProperties.setAttributeNS(NS_W3_XMLNS, XMLNS_XADES, NS_ETSI_1_3_2);
        signedProperties.setAttribute(XML_ATTRIBUTE_ID, "xades-" + signedPropertiesId);
        qualifyingProperties.appendChild(signedProperties);
        Element signedSignatureProperties = document.createElementNS(NS_ETSI_1_3_2, XADES_PREFIX + XADES_SIGNED_SIGNATURE_PROPERTIES);
        signedProperties.appendChild(signedSignatureProperties);
        Element signingTimeElement = document.createElementNS(NS_ETSI_1_3_2, XADES_PREFIX + XADES_SIGNING_TIME);
        final XMLGregorianCalendar xmlGregorianCalendar = se.signatureservice.support.common.utils.DateUtils.createXMLGregorianCalendar(signingTime);
        final String xmlSigningTime = xmlGregorianCalendar.toXMLFormat();
        signingTimeElement.appendChild(document.createTextNode(xmlSigningTime));
        signedSignatureProperties.appendChild(signingTimeElement);

        if(signingCertificate != null) {
            Element signingCertificateV2 = document.createElementNS(NS_ETSI_1_3_2, XADES_PREFIX + XADES_SIGNING_CERTIFICATE_V2);
            Element cert = document.createElementNS(NS_ETSI_1_3_2, XADES_PREFIX + XADES_CERT);
            Element certDigest = document.createElementNS(NS_ETSI_1_3_2, XADES_PREFIX + XADES_CERT_DIGEST);
            Element digestMethod = document.createElementNS(NS_W3_XMLDSIG, DS_PREFIX + DS_DIGESTMETHOD);
            digestMethod.setAttribute(XML_ATTRIBUTE_ALGORITHM, signAlgorithm.getDigestAlgo());
            certDigest.appendChild(digestMethod);
            Element digestValue = document.createElementNS(NS_W3_XMLDSIG, DS_PREFIX + DS_DIGESTVALUE);
            byte[] certDigestValue = MessageDigest.getInstance(signAlgorithm.getMessageDigestName()).digest(signingCertificate.getEncoded());
            digestValue.appendChild(document.createTextNode(new String(Base64.encode(certDigestValue))));
            certDigest.appendChild(digestValue);
            cert.appendChild(certDigest);
            Element issuerSerialV2 = document.createElementNS(NS_ETSI_1_3_2, XADES_PREFIX + XADES_ISSUER_SERIAL_V2);
            X500Name issuerX500Name = new X509CertificateHolder(signingCertificate.getEncoded()).getIssuer();
            GeneralName generalName = new GeneralName(issuerX500Name);
            GeneralNames generalNames = new GeneralNames(generalName);
            BigInteger serialNumber = signingCertificate.getSerialNumber();
            IssuerSerial issuerSerial = new IssuerSerial(generalNames, new ASN1Integer(serialNumber));
            issuerSerialV2.appendChild(document.createTextNode(new String(Base64.encode(issuerSerial.toASN1Primitive().getEncoded(ASN1Encoding.DER)))));
            cert.appendChild(issuerSerialV2);
            signingCertificateV2.appendChild(cert);
            signedSignatureProperties.appendChild(signingCertificateV2);
        }

        Element signedDataObjectProperties = document.createElementNS(NS_ETSI_1_3_2, XADES_PREFIX + XADES_SIGNED_DATA_OBJECT_PROPERTIES);
        Element dataObjectFormat = document.createElementNS(NS_ETSI_1_3_2, XADES_PREFIX + XADES_DATA_OBJECT_FORMAT);
        dataObjectFormat.setAttribute(XML_ATTRIBUTE_OBJECT_REFERENCE, "#r-id-1");
        Element mimeType = document.createElementNS(NS_ETSI_1_3_2, XADES_PREFIX + XADES_MIME_TYPE);
        mimeType.appendChild(document.createTextNode(XML_MIMETYPE));
        dataObjectFormat.appendChild(mimeType);
        signedDataObjectProperties.appendChild(dataObjectFormat);
        signedProperties.appendChild(signedDataObjectProperties);

        // Calculate new digest based on the correct SignedProperties
        byte[] updatedDigest = getSignedPropertiesDigest(canonicalizationMethod, signAlgorithm.getMessageDigestName(), signedProperties);

        // Locate and update digest and reference ID within signedInfo
        if(!updateXAdESReference(signedInfo, "#xades-" + signedPropertiesId, updatedDigest)){
            // If XAdES reference was not found we construct it from scratch.
            createSignedPropertiesReference(signedInfo, signedPropertiesId, canonicalizationMethod, signAlgorithm.getDigestAlgo(), updatedDigest);
        }

        // Canonicalize and update sign task
        Canonicalizer c14n = Canonicalizer.getInstance(canonicalizationMethod);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        signTask.setToBeSignedBytes(c14n.canonicalizeSubtree(signedInfo));

        if(signTask.getAdESObject() == null){
            signTask.setAdESObject(new AdESObjectType());
        }

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        DOMSource source = new DOMSource(object);
        baos = new ByteArrayOutputStream();
        StreamResult result = new StreamResult(baos);
        transformer.transform(source, result);

        signTask.getAdESObject().setAdESObjectBytes(baos.toByteArray());

        // If we dont have the signing certificate we set an empty signatureId. In this way
        // the backend will generate a proper signatureId once the certifcate is generated.
        signTask.getAdESObject().setSignatureId(signingCertificate != null ? signedPropertiesId : null);
    }

    /**
     * Update XAdES object reference (with the type 'http://uri.etsi.org/01903#SignedProperties')
     * within signedinfo structure with new URI and digest value. Only the first reference found
     * is updated.
     *
     * @param signedInfo SignedInfo structure to update
     * @param referenceURI New reference URI value
     * @param digestValue New digest value
     * @return true if reference was found and updated, otherwise false
     */
    static boolean updateXAdESReference(Document signedInfo, String referenceURI, byte[] digestValue) throws UnsupportedEncodingException {
        NodeList references = signedInfo.getElementsByTagNameNS(NS_W3_XMLDSIG, DS_REFERENCE);
        for (int i = 0; i < references.getLength(); i++) {
            Element reference = ((Element) references.item(i));
            String type = reference.getAttribute(XML_ATTRIBUTE_TYPE);
            if (type != null && type.equalsIgnoreCase(NS_ETSI_1_3_2_SIGNED_PROPERTIES)) {
                reference.setAttribute(XML_ATTRIBUTE_URI, referenceURI);
                Element element = (Element)reference.getElementsByTagNameNS(NS_W3_XMLDSIG, DS_DIGESTVALUE).item(0);
                element.getFirstChild().setNodeValue(new String(Base64.encode(digestValue), "UTF-8"));
                return true;
            }
        }
        return false;
    }

    /**
     * Get ID to use for XAdES object.
     *
     * @param signTask Sign task related to the XAdES object or null if not available.
     * @param signingTime Time when signature was performed
     * @param signingCertificate Signing certificate or null if not available.
     * @return signature ID from signtask if available. Otherwise a deterministic ID generated
     * according to ESig DSS library if signing certificate is available. Last resort is a randomly generated ID.
     */
    static String getSignedPropertiesId(SignTaskDataType signTask, Date signingTime, X509Certificate signingCertificate){
        String signedPropertiesId;

        if(signTask != null && signTask.getAdESObject() != null && signTask.getAdESObject().getSignatureId() != null){
            // If signatureId is present within the signtask we must use it when
            // constructing the AdES-object accoring to The Swedish E-identification Board
            // specification ELN-0609:4.1.1.1
            signedPropertiesId = signTask.getAdESObject().getSignatureId();
        } else if(signingCertificate != null) {
            // If signing certificate is present we generate deterministic ID according to
            // esig dss signature library.
            signedPropertiesId = generateDeterministicId(signingCertificate, signingTime, "id-");
        } else {
            signedPropertiesId = generateRandomId("id-");
        }

        return signedPropertiesId;
    }

    private static String generateRandomId(String prefix){
        return prefix + UUID.randomUUID().toString().toLowerCase();
    }

    /**
     * Calculate deterministic ID to use within SignedInfo structure when incorporating
     * signing certificate.
     * @param x509Certificate Signing certificate part of the signature process
     * @param signingTime Signature time
     * @return Deterministic ID
     */
    private static String generateDeterministicId(X509Certificate x509Certificate, Date signingTime, String prefix){
        String deterministicId;
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);

            if (signingTime != null) {
                dos.writeLong(signingTime.getTime());
            }
            if(x509Certificate != null){
                byte[] certDigest = MessageDigest.getInstance("SHA-256").digest(x509Certificate.getEncoded());
                String xmlId = DSS_CERTIFICATETOKEN_XMLID_PREFIX + DatatypeConverter.printHexBinary(certDigest).toUpperCase();
                dos.writeChars(xmlId);
            }
            dos.flush();
            deterministicId = prefix + DatatypeConverter.printHexBinary(MessageDigest.getInstance("MD5").digest(baos.toByteArray())).toLowerCase();
        } catch(Exception e){
            return null;
        }
        return deterministicId;
    }

    /**
     * Calculate digest of SignedProperties element
     *
     * @param canonicalizationMethod Canonicalization method to use
     * @param digestAlgorithm Digest algorithm to use
     * @param signedProperties SignedProperties to calculate digest of
     * @return Digest value of given SignedProperties
     */
    private static byte[] getSignedPropertiesDigest(String canonicalizationMethod, String digestAlgorithm, Element signedProperties) {
        byte[] digestValue = null;
        try {
            Canonicalizer c14n = Canonicalizer.getInstance(canonicalizationMethod);
            byte[] canonicalized = c14n.canonicalizeSubtree(signedProperties);
            MessageDigest messageDigest = MessageDigest.getInstance(digestAlgorithm);
            digestValue = messageDigest.digest(canonicalized);
        } catch(Exception e){
            e.printStackTrace();
        }
        return digestValue;
    }

    /**
     * Get list of AuthnContextClassRefs to request for a given authentication service.
     *
     * @param authenticationServiceId Authentication service identifier to get AuthnContextClassRefs for.
     * @param config Support service configuration to use.
     * @return List of AuthnContextClassRefs to request.
     */
    private List<String> getAuthnContextClassRefs(String authenticationServiceId, SupportConfiguration config){
        List<String> accRefs = new ArrayList<>();

        if(config.getAuthnContextClassRef() != null){
            log.warn("Profile configuration 'authnContextClassRef' is deprecated. Please remove it and use 'defaultAuthnContextClassRefs' instead.");
            accRefs.add(config.getAuthnContextClassRef());
        }

        // We allow both singular and plural definitions of what AuthnContextClassRef(s) to request
        // for the given authentication provider, for both default values and for explicit values
        // configured for each individual authentication provider.

        if(config.getDefaultAuthnContextClassRef() != null){
            if(!accRefs.contains(config.getDefaultAuthnContextClassRef())){
                accRefs.add(config.getDefaultAuthnContextClassRef());
            }
        }

        if(config.getDefaultAuthnContextClassRefs() != null){
            for(String ref : config.getDefaultAuthnContextClassRefs()){
                if(!accRefs.contains(ref)){
                    accRefs.add(ref);
                }
            }
        }

        // If any explicit values are defined for the individual authenticatioon providers
        // then they will override any default values previously defined.

        List<String> explicitAccRefs = new ArrayList<>();
        if(config.getTrustedAuthenticationServices() != null){
            for(Map.Entry<String,Map> entry : config.getTrustedAuthenticationServices().entrySet()){
                if(entry.getValue().get("entityId").equals(authenticationServiceId)){
                    explicitAccRefs.add((String)entry.getValue().get("authnContextClassRef"));
                }

                if(entry.getValue().get("authnContextClassRefs") != null){
                    for(String ref : (List<String>)entry.getValue().get("authnContextClassRefs")){
                        if(!explicitAccRefs.contains(ref)){
                            explicitAccRefs.add(ref);
                        }
                    }
                }
            }
        }

        return (explicitAccRefs.isEmpty() ? accRefs : explicitAccRefs);
    }

    private String getUserIdAttributeMapping(String authenticationServiceId, SupportConfiguration config){
        if(config.getUserIdAttributeMapping() != null){
            log.warn("Profile configuration 'userIdAttributeMapping' is deprecated. Please remove it and use 'defaultUserIdAttributeMapping' instead.");
        }

        String userIdAttributeMapping = config.getDefaultUserIdAttributeMapping();
        if(userIdAttributeMapping == null){
            userIdAttributeMapping = config.getUserIdAttributeMapping();
        }

        if(config.getTrustedAuthenticationServices() != null){
            for(Map.Entry<String, Map> entry : config.getTrustedAuthenticationServices().entrySet()){
                if(entry.getValue().get("entityId").equals(authenticationServiceId) && entry.getValue().get("userIdAttributeMapping") != null){
                    userIdAttributeMapping = (String)entry.getValue().get("userIdAttributeMapping");
                }
            }
        }

        return userIdAttributeMapping;
    }

    /**
     * Create new reference to XAdES SignedProperties and incorporate it into given SignedInfo.
     *
     * @param signedInfo SignedInfo document to incorporate reference into
     * @param signedPropertiesId ID to use for the reference
     * @param canonicalizationMethod Canonicalization method to use for the reference
     * @param digestAlgorithm Digest algorithm to use for the reference
     * @param digestValue Digest value to use for the reference
     */
    static void createSignedPropertiesReference(Document signedInfo, String signedPropertiesId, String canonicalizationMethod, String digestAlgorithm, byte[] digestValue){
        Element referenceElement = signedInfo.createElementNS(NS_W3_XMLDSIG, DS_PREFIX + DS_REFERENCE);
        signedInfo.getDocumentElement().appendChild(referenceElement);
        referenceElement.setAttribute(XML_ATTRIBUTE_TYPE, NS_ETSI_1_3_2_SIGNED_PROPERTIES);
        referenceElement.setAttribute(XML_ATTRIBUTE_URI, "#xades-" + signedPropertiesId);

        Element transformsElement = signedInfo.createElementNS(NS_W3_XMLDSIG, DS_PREFIX + DS_TRANSFORMS);
        referenceElement.appendChild(transformsElement);
        Element transformElement = signedInfo.createElementNS(NS_W3_XMLDSIG, DS_PREFIX + DS_TRANSFORM);
        transformsElement.appendChild(transformElement);
        transformElement.setAttribute(XML_ATTRIBUTE_ALGORITHM, canonicalizationMethod);
        Element digestMethodElement = signedInfo.createElementNS(NS_W3_XMLDSIG, DS_PREFIX + DS_DIGESTMETHOD);
        referenceElement.appendChild(digestMethodElement);
        digestMethodElement.setAttribute(XML_ATTRIBUTE_ALGORITHM, digestAlgorithm);
        Element digestValueElement = signedInfo.createElementNS(NS_W3_XMLDSIG, DS_PREFIX + DS_DIGESTVALUE);
        referenceElement.appendChild(digestValueElement);
        digestValueElement.setTextContent(new String(Base64.encode(digestValue)));
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
    private ConditionsType generateConditions(GregorianCalendar requestTime, String consumerURL, SupportConfiguration config) throws ServerErrorException {
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
    private GregorianCalendar getNotBefore(GregorianCalendar requestTime, SupportConfiguration config) {
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
    private GregorianCalendar getNotOnOrAfter(GregorianCalendar requestTime, SupportConfiguration config) {
        GregorianCalendar notOnOrAfter = new GregorianCalendar();
        notOnOrAfter.setTime(requestTime.getTime());
        notOnOrAfter.add(GregorianCalendar.MINUTE, config.getSignatureValidityMinutes());
        return notOnOrAfter;
    }

    private SystemTime getSystemTime() {
        if(systemTime == null){
            systemTime = new DefaultSystemTime();
        }

        return systemTime;
    }

    /**
     * Ensures that a transaction ID is valid to use in the system.
     *
     * @param transactionId transaction ID to validate
     * @throws ClientErrorException if given transaction ID is not valid
     */
    private void validateTransactionId(String transactionId) throws ClientErrorException {
        if(transactionId == null || transactionId.length() < 32){
            throw (ClientErrorException)ErrorCode.UNSUPPORTED_TRANSACTION_ID.toException("Transaction ID is too short");
        }
    }

    /**
     * Ensures that there are no obvious errors within a set of documents
     *
     * @param documents Documents to validate
     */
    private void validateDocuments(DocumentRequests documents) throws ClientErrorException {
        if(documents == null){
            throw (ClientErrorException) ErrorCode.INVALID_DOCUMENT.toException("No documents to be signed", messageSource);
        }

        if(documents.documents == null || documents.documents.size() == 0){
            throw (ClientErrorException)ErrorCode.INVALID_DOCUMENT.toException("Empty list of documents to be signed", messageSource);
        }

        for(Object object : documents.documents){
            if(object instanceof DocumentSigningRequest){
                DocumentSigningRequest document = (DocumentSigningRequest) object;
                if(document.name == null || document.name.length() == 0){
                    throw (ClientErrorException)ErrorCode.INVALID_DOCUMENT.toException("Missing document name", messageSource);
                }

                if(document.data == null){
                    throw (ClientErrorException)ErrorCode.INVALID_DOCUMENT.toException("Missing data for document (${it.name})", messageSource);
                }

                if(document.type == null || document.type.length() == 0){
                    throw (ClientErrorException)ErrorCode.INVALID_MIMETYPE.toException("Missing document type for document (${it.name})", messageSource);
                }

                if(MimeType.getFileExtension(document.name) != null && !MimeType.fromFileName(document.name).getMimeTypeString().equals(document.type)){
                    throw (ClientErrorException)ErrorCode.INVALID_MIMETYPE.toException("Invalid type (${it.type}) for document name (${it.name}). ${MimeType.fromFileName(it.name).mimeTypeString} was exptected.", messageSource);
                }
            } else if(object instanceof DocumentRef) {
                throw (ClientErrorException)ErrorCode.UNSUPPORTED_OPERATION.toException("Document references are not supported", messageSource);
            }
        }
    }

    /**
     * Validates a consumer URL against configuration.
     *
     * @param consumerURL URL to validate
     * @param config Configuration to validate against
     * @return true if consumer URL is valid and authorized
     * @throws ServerErrorException If consumer URL is not authorized to use
     */
    private boolean validateConsumerURL(String consumerURL, SupportConfiguration config) throws ServerErrorException {
        boolean authorized = false;
        if(config.getAuthorizedConsumerURLs() != null){
            for(String url : config.getAuthorizedConsumerURLs()){
                if(consumerURL.startsWith(url)){
                    authorized = true;
                }
            }
        } else {
            log.warn("No authorized consumer URLs specified in configuration");
        }

        if(!authorized){
            throw (ServerErrorException)ErrorCode.INVALID_CONFIGURATION.toException("Unauthorized consumer URL: " + consumerURL + ".");
        }

        return authorized;
    }

    private void validateAuthenticationServiceId(String authenticationServiceId, SupportConfiguration config) throws ClientErrorException {
        boolean validated = false;

        if(config != null){
            Map<String,Map> trustedAuthenticationServices = config.getTrustedAuthenticationServices();
            if(trustedAuthenticationServices != null){
                for(Map map : config.getTrustedAuthenticationServices().values()){
                    if(map.get("entityId") != null && map.get("entityId").equals(authenticationServiceId)){
                        validated = true;
                    }
                }
            } else {
                log.warn("No trusted authentication services are specified in configuration.");
            }
        }

        if(!validated){
            throw (ClientErrorException)ErrorCode.UNAUTHORIZED_AUTH_SERVICE.toException("Unauthorized authentication service (" + authenticationServiceId + ")", messageSource);
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
        public Builder(){
            config = new SupportAPIConfiguration();
        }

        /**
         * Specify a custom message source to use when resolving error messages.
         *
         * @param messageSource Message source to use.
         * @return Updated builder.
         */
        public Builder messageSource(MessageSource messageSource){
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
        public Builder messageSecurityProvider(MessageSecurityProvider messageSecurityProvider){
            config.setMessageSecurityProvider(messageSecurityProvider);
            return this;
        }

        public Builder cacheProvider(CacheProvider cacheProvider) {
            config.setCacheProvider(cacheProvider);
            return this;
        }

        /**
         * Specify a SSL truststore to use when validating documents and signatures.
         *
         * @param trustStorePath Path to trust store. This could point to either
         *                       a path on the classpath or on the file system,
         *                       with classpath having higher priority.
         * @return Updated builder
         */
        public Builder trustStore(String trustStorePath){
            config.setTrustStorePath(trustStorePath);
            return this;
        }

        /**
         * Specify the password that protects the truststore. This is required
         * if sslTrustStore is specified.
         *
         * @param trustStorePassword Password that protects the trust store
         * @return Updated builder
         */
        public Builder trustStorePassword(String trustStorePassword){
            config.setTrustStorePassword(trustStorePassword);
            return this;
        }

        /**
         * Specify the truststore type. Default is "JKS".
         *
         * @param trustStoreType Type of truststore being used.
         * @return Updated builder
         */
        public Builder trustStoreType(String trustStoreType){
            config.setTrustStoreType(trustStoreType);
            return this;
        }

        /**
         * Specify custom policy file to use from the class path when validating documents.
         *
         * @param policy Policy file to use.
         * @return Updated builder.
         */
        public Builder validationPolicy(String policy){
            config.setValidationPolicy(policy);
            return this;
        }

        /**
         * Specify if strict validation should be performed when validating documents.
         *
         * @param strictValidation True if strict validation should be performed, otherwise false.
         * @return Updated builder.
         */
        public Builder performStrictValidation(boolean strictValidation){
            config.setPerformStrictValidation(strictValidation);
            return this;
        }

        /**
         * Specify if revocation check should be performed when validating documents.
         *
         * @param revocationCheck True if revocation check should be performed, otherwise false.
         * @return Updated builder.
         */
        public Builder disableRevocationCheck(boolean revocationCheck){
            config.setDisableRevocationCheck(revocationCheck);
            return this;
        }

        /**
         * Add list of recipient certificates to use when generating encrypted sign messages.
         *
         * @param authenticationServiceId Authentication service to add recipient for.
         * @param recipients Recipients of encrypted sign messages.
         * @return Updated builder.
         */
        public Builder signMessageRecipients(String authenticationServiceId, List<X509Certificate> recipients){
            if(!config.getEncryptedSignMessageRecipients().containsKey(authenticationServiceId)){
                config.getEncryptedSignMessageRecipients().put(authenticationServiceId, new ArrayList<>());
            }
            config.getEncryptedSignMessageRecipients().get(authenticationServiceId).addAll(recipients);
            return this;
        }

        /**
         * Add recipient certificate to use when generating encrypted sign messages.
         *
         * @param authenticationServiceId Authentication service to add recipients for.
         * @param recipient Recipient of encrypted sign messages.
         * @return Updated builder.
         */
        public Builder signMessageRecipient(String authenticationServiceId, X509Certificate recipient){
            if(!config.getEncryptedSignMessageRecipients().containsKey(authenticationServiceId)){
                config.getEncryptedSignMessageRecipients().put(authenticationServiceId, new ArrayList<>());
            }
            config.getEncryptedSignMessageRecipients().get(authenticationServiceId).add(recipient);
            return this;
        }

        /**
         * Build the transaction signer.
         *
         * @return TransactionSigner instance based on builder settings.
         */
        public SupportServiceAPI build() {
            return new V2SupportServiceAPI(config);
        }
    }

    public static void main(String args[]) throws ClientErrorException, ServerErrorException, IOException, MessageProcessingException {
        // 1) Create a message security provider.
        MessageSecurityProvider messageSecurityProvider = SupportLibraryUtils.createSimpleMessageSecurityProvider(
            "/home/agerbergt/git/signservice/signservice-support/src/test/resources/keystores/rsasigner.p12",
            "FKBA9a",
            "702221c823a70a80;cn=lab mock issuing ca,o=lab,c=se",
            "/home/agerbergt/git/signservice/signservice-support/src/test/resources/keystores/validation-truststore.jks",
            "foo123"
        );

        // 2) Build an instance of the support service API
        SupportServiceAPI supportServiceAPI = new V2SupportServiceAPI.Builder()
                .messageSecurityProvider(messageSecurityProvider)
                .cacheProvider(new DummyCacheProvider())
                .build();

        // 3) Create user that is going to sign the document(s)
        User user = new User();
        user.setUserId("190101010001");

        // 4) Create profile configuration to use for the transaction. This can be re-used.
        SupportConfiguration profileConfig = new SupportConfiguration.Builder()
                .addTrustedAuthenticationService(
                        "testIdpST",
                        "https://test.idp.signatureservice.se/samlv2/idp/metadata",
                        "Signature Service Test iDP")
                .addAuthorizedConsumerURL("http://localhost")
                .build();

        // 5) Create document requests to include in the transaction.
        DocumentRequests documentRequests = new DocumentRequests.Builder()
                .addXMLDocument("/home/agerbergt/git/signservice/signservice-support/src/test/resources/testdocument.xml")
                .build();

        // 6) Generate the signature request
        PreparedSignatureInfo preparedSignatureInfo = supportServiceAPI.prepareSignature(
                profileConfig,
                documentRequests,
                null,
                "Im signing everything",
                user,
                "https://test.idp.signatureservice.se/samlv2/idp/metadata",
                "http://localhost",
                null
        );

        System.out.println(preparedSignatureInfo.getPreparedSignature().getSignRequest());
    }
}
