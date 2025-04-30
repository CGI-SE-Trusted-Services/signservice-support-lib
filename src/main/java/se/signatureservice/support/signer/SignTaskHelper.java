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
package se.signatureservice.support.signer;

import org.apache.commons.lang3.time.DateUtils;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.encoders.Base64;
import se.signatureservice.messages.MessageProcessingException;
import se.signatureservice.messages.dss1.core.jaxb.SignResponse;
import se.signatureservice.messages.sweeid2.dssextenstions1_1.SigType;
import se.signatureservice.messages.sweeid2.dssextenstions1_1.jaxb.AdESObjectType;
import se.signatureservice.messages.sweeid2.dssextenstions1_1.jaxb.SignResponseExtensionType;
import se.signatureservice.messages.sweeid2.dssextenstions1_1.jaxb.SignTaskDataType;
import se.signatureservice.messages.sweeid2.dssextenstions1_1.jaxb.SignTasksType;
import se.signatureservice.messages.utils.CertUtils;
import se.signatureservice.messages.utils.DefaultSystemTime;
import se.signatureservice.messages.utils.SystemTime;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import se.signatureservice.configuration.common.InvalidArgumentException;
import se.signatureservice.support.common.keygen.SignAlgorithm;

import jakarta.xml.bind.DatatypeConverter;
import jakarta.xml.bind.JAXBElement;
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
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Helper class that contains functionality needed when generating, preparing
 * and processing signature related data.
 *
 * @author Tobias Agerberg
 */
public class SignTaskHelper {
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

    private static DocumentBuilderFactory documentBuilderFactory;
    private final SystemTime systemTime;

    /**
     * SignTaskHelper Constructor.
     *
     * @param systemTime SystemTime to use, or null to use default.
     */
    public SignTaskHelper(SystemTime systemTime) {
        this.systemTime = Objects.requireNonNullElseGet(systemTime, DefaultSystemTime::new);
    }

    /**
     * Create new XaDES-object from scratch that will be used during the signature process for
     * advanced XML signatures (XAdES).
     * @param signTask Sign task to update with new XAdES-object
     * @param signTransformation Signature transformation that is used.
     * @param signingCertificate Signature certificate that will be used to sign the ToBeSignedBytes
     * @param explicitSigningTime Signing time to use or null to use the current system time.
     */
    public void createNewXadesObject(SignTaskDataType signTask, String signTransformation, X509Certificate signingCertificate, Date explicitSigningTime) throws MessageProcessingException, IOException, SAXException, ParserConfigurationException, TransformerException, InvalidCanonicalizerException, CertificateEncodingException, NoSuchAlgorithmException, CanonicalizationException {
        SignAlgorithm signAlgorithm = SignAlgorithm.getAlgoByJavaName(signTransformation);
        DocumentBuilder documentBuilder = getSignedInfoDocumentBuilder();
        org.w3c.dom.Document signedInfo = documentBuilder.parse(new ByteArrayInputStream(signTask.getToBeSignedBytes()));

        // We re-use the same canonicalization algorithm so we dont have to
        // handle split-configuration between signservice-support and signservice-backend.
        NodeList nodeList = signedInfo.getElementsByTagNameNS(NS_W3_XMLDSIG, DS_CANONICALIZATIONMETHOD);
        Element canonicalizationMethodElement = nodeList != null ? (Element)signedInfo.getElementsByTagNameNS(NS_W3_XMLDSIG, DS_CANONICALIZATIONMETHOD).item(0) : null;
        String canonicalizationMethod = null;
        if(canonicalizationMethodElement != null) {
            canonicalizationMethod = canonicalizationMethodElement.getAttribute(XML_ATTRIBUTE_ALGORITHM);
        }

        Date signingTime = explicitSigningTime;
        if(signingTime == null){
            signingTime = DateUtils.round(this.systemTime.getSystemTime(), Calendar.SECOND);
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
        final XMLGregorianCalendar xmlGregorianCalendar = se.signatureservice.support.utils.DateUtils.createXMLGregorianCalendar(signingTime);
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
        dataObjectFormat.setAttribute(XML_ATTRIBUTE_OBJECT_REFERENCE, generateDeterministicId(null, signingTime, "#r-id-", "-1"));
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
        ByteArrayOutputStream signedInfoStream = new ByteArrayOutputStream();
        c14n.canonicalizeSubtree(signedInfo, signedInfoStream);
        signTask.setToBeSignedBytes(signedInfoStream.toByteArray());

        if(signTask.getAdESObject() == null){
            signTask.setAdESObject(new AdESObjectType());
        }

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        DOMSource source = new DOMSource(object);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        StreamResult result = new StreamResult(baos);
        transformer.transform(source, result);

        signTask.getAdESObject().setAdESObjectBytes(baos.toByteArray());

        // If we dont have the signing certificate we set an empty signatureId. In this way
        // the backend will generate a proper signatureId once the certifcate is generated.
        signTask.getAdESObject().setSignatureId(signingCertificate != null ? signedPropertiesId : null);
    }

    /**
     * Get DocumentBuilderFactory to use when creating new instance of
     * DocumentBuilder. This is shared across threads.
     * @return DocumentBuilderFactory
     */
    private static DocumentBuilderFactory getSignedInfoDocumentBuilderFactory(){
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
    private static DocumentBuilder getSignedInfoDocumentBuilder() throws ParserConfigurationException {
        return getSignedInfoDocumentBuilderFactory().newDocumentBuilder();
    }

    /**
     * Retrieve Xades signing time from a sign task
     * @param signTask Sign task to retrieve xades signing time from
     * @return Signing time in xades object or null if not found
     */
    public static Date getXadesSigningTime(SignTaskDataType signTask) throws ParserConfigurationException, IOException, SAXException {
        Date signingTime = null;

        if(signTask == null || signTask.getAdESObject() == null || signTask.getAdESObject().getAdESObjectBytes() == null){
            return null;
        }

        Document xadesObject = getSignedInfoDocumentBuilder().parse(new ByteArrayInputStream(signTask.getAdESObject().getAdESObjectBytes()));
        NodeList nodeList = xadesObject.getElementsByTagNameNS(NS_ETSI_1_3_2, XADES_SIGNING_TIME);
        if(nodeList.getLength() > 0){
            Element element = (Element)nodeList.item(0);
            signingTime = se.signatureservice.support.utils.DateUtils.parseXMLDate(element.getFirstChild().getTextContent());
        }

        return signingTime;
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
    private static void createSignedPropertiesReference(Document signedInfo, String signedPropertiesId, String canonicalizationMethod, String digestAlgorithm, byte[] digestValue){
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
    private static boolean updateXAdESReference(Document signedInfo, String referenceURI, byte[] digestValue) throws UnsupportedEncodingException {
        NodeList references = signedInfo.getElementsByTagNameNS(NS_W3_XMLDSIG, DS_REFERENCE);
        for (int i = 0; i < references.getLength(); i++) {
            Element reference = ((Element) references.item(i));
            String type = reference.getAttribute(XML_ATTRIBUTE_TYPE);
            if (type.equalsIgnoreCase(NS_ETSI_1_3_2_SIGNED_PROPERTIES)) {
                reference.setAttribute(XML_ATTRIBUTE_URI, referenceURI);
                Element element = (Element)reference.getElementsByTagNameNS(NS_W3_XMLDSIG, DS_DIGESTVALUE).item(0);
                element.getFirstChild().setNodeValue(new String(Base64.encode(digestValue), StandardCharsets.UTF_8));
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
    private static String getSignedPropertiesId(SignTaskDataType signTask, Date signingTime, X509Certificate signingCertificate){
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

    /**
     * Generate random ID with prefix.
     *
     * @param prefix Prefix to use for random ID.
     * @return Random ID with given prefix.
     */
    private static String generateRandomId(String prefix){
        return prefix + UUID.randomUUID().toString().toLowerCase();
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
            ByteArrayOutputStream signedPropertiesStream = new ByteArrayOutputStream();
            c14n.canonicalizeSubtree(signedProperties, signedPropertiesStream);
            MessageDigest messageDigest = MessageDigest.getInstance(digestAlgorithm);
            digestValue = messageDigest.digest(signedPropertiesStream.toByteArray());
        } catch(Exception e){
            e.printStackTrace();
        }
        return digestValue;
    }

    /**
     * Calculate deterministic ID to use within SignedInfo structure when incorporating
     * signing certificate, with a given prefix.
     *
     * @param x509Certificate Signing certificate part of the signature process
     * @param signingTime Signature time
     * @param prefix Prefix to use for resulting deterministic ID.
     * @return Deterministic ID
     */
    public static String generateDeterministicId(X509Certificate x509Certificate, Date signingTime, String prefix){
        return generateDeterministicId(x509Certificate, signingTime, prefix, null);
    }

    /**
     * Calculate deterministic ID to use within SignedInfo structure when incorporating
     * signing certificate, with a given prefix and suffix.
     *
     * @param x509Certificate Signing certificate part of the signature process
     * @param signingTime Signature time
     * @param prefix Prefix to use for resulting deterministic ID.
     * @param suffix Suffix to use for resulting deterministic ID.
     * @return Deterministic ID
     */
    public static String generateDeterministicId(X509Certificate x509Certificate, Date signingTime, String prefix, String suffix){
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
            deterministicId = prefix + DatatypeConverter.printHexBinary(MessageDigest.getInstance("MD5").digest(baos.toByteArray())).toLowerCase() + (suffix != null ? suffix : "");
        } catch(Exception e){
            return null;
        }
        return deterministicId;
    }

    /**
     * Check if signature type in signtask is XML/Xades
     * @param signTask Signtask to check
     * @return true if xml/xades otherwise false
     */
    public static boolean isXadesSignTask(SignTaskDataType signTask){
        return signTask.getSigType().equals(SigType.XML.name()) && signTask.getAdESType() != null;
    }

    /**
     * Check if signature type in signtask is CMS/Cades
     * @param signTask Signtask to check
     * @return true if cms/cades otherwise false
     */
    public static boolean isCadesSignTask(SignTaskDataType signTask){
        return signTask.getSigType().equals(SigType.CMS.name()) && signTask.getAdESType() != null;
    }

    /**
     * Check if signature type in signtask is PDF/Pades
     * @param signTask Signtask to check
     * @return true if pdf/pades otherwise false
     */
    public static boolean isPadesSignTask(SignTaskDataType signTask){
        return signTask.getSigType().equals(SigType.PDF.name()) && signTask.getAdESType() != null;
    }

    /**
     * Retrieve list of sign tasks available within a given sign response.
     *
     * @param signResponse Sign response to retrieve sign tasks from
     * @return List of sign tasks within sign request
     * @throws InvalidArgumentException If no sign tasks could be found in sign request.
     */
    public static List<SignTaskDataType> getSignTasks(SignResponse signResponse) throws InvalidArgumentException {
        if(signResponse != null && signResponse.getSignatureObject() != null && signResponse.getSignatureObject().getOther() != null){
            List<Object> anyObjects = signResponse.getSignatureObject().getOther().getAny();
            if(anyObjects != null) {
                for(Object anyObject : anyObjects) {
                    if(anyObject instanceof JAXBElement) {
                        JAXBElement e = (JAXBElement)anyObject;
                        if(e.getValue() instanceof SignTasksType) {
                            SignTasksType s = (SignTasksType)e.getValue();
                            return s.getSignTaskData();
                        }
                    }
                }
            }
        }

        throw new InvalidArgumentException("Error no SignTasks found in response.");
    }

    /**
     * Retrieve list of certificates that builds up the signature certificate chain
     * for a given signature response.
     * @param signResponse Sogm response to retrieve certificate chain from
     * @return List of certificates that builds the signing certificate chain for the given sign response
     */
    public static List<X509Certificate> getSignatureCertificateChain(SignResponse signResponse) throws CertificateException {
        List<X509Certificate> chain = new ArrayList<>();
        if(signResponse != null && signResponse.getOptionalOutputs() != null) {
            for (Object o : signResponse.getOptionalOutputs().getAny()) {
                if (o instanceof JAXBElement) {
                    JAXBElement e = (JAXBElement) o;
                    if (e.getValue() instanceof SignResponseExtensionType) {
                        SignResponseExtensionType ext = (SignResponseExtensionType) e.getValue();

                        for(byte[] buf : ext.getSignatureCertificateChain().getX509Certificate()){
                            chain.add(CertUtils.getCertfromByteArray(buf));
                        }
                    }
                }
            }
        }
        return chain;
    }
}
