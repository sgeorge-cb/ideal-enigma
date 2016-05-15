package org.caringbridge.client.security.services;
import java.io.ByteArrayInputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.zip.Inflater;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

@Service
public class SAMLService{

	public static String SP_ENDPOINT = "http://www.sgeorge.dev:8080/consume.jsp";
	private static String IDP_ISSUER = "http://www.caringbridge.org";
	private static String AUDIENCE = "com:sample:spring:sp";
	
    @Bean
    public KeyManager keyManager() {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        Resource storeFile = loader
                .getResource("classpath:/saml/cb2056.jks");
        String storePass = "nalle123";
        Map<String, String> passwords = new HashMap<String, String>();
        passwords.put("cb2056", "nalle123");
        String defaultKey = "cb2056";
        return new JKSKeyManager(storeFile, storePass, passwords, defaultKey);
    }
    
	public String debugprintSAMLObject(SAMLObject samlObject) throws Exception{
	    try {
	    	ResponseMarshaller marshaller = new ResponseMarshaller();
	        Element element = marshaller.marshall(samlObject);
	        System.out.println("++++++++++++++++++++++++++++++");
	        System.out.println(XMLHelper.nodeToString(element));
	        System.out.println("++++++++++++++++++++++++++++++");
	        System.out.println(Base64.encode(XMLHelper.nodeToString(element).getBytes()));
            System.out.println("++++++++++++++++++++++++++++++");
	       return XMLHelper.prettyPrintXML(element);
	    } catch (MarshallingException e) {
	    	e.printStackTrace();
	    }
	    return null;
	}

	public String getSamlResponse(String userId, String inResponseTo, String spEndPoint) throws Exception {
		DefaultBootstrap.bootstrap();
		Response response = generateValidSAMLResponse(userId, inResponseTo,spEndPoint!=null? spEndPoint : SP_ENDPOINT);
    	ResponseMarshaller marshaller = new ResponseMarshaller();
    	debugprintSAMLObject(response); //Just for debugging
        Element element = marshaller.marshall(response);
        return Base64.encode(XMLHelper.nodeToString(element).getBytes());
	}

	private Response generateValidSAMLResponse(String userId, String inResponseTo, String spEndPoint) throws Exception {
    	Response response = (Response) Configuration.getBuilderFactory()
                .getBuilder(Response.DEFAULT_ELEMENT_NAME)
                .buildObject(Response.DEFAULT_ELEMENT_NAME);    	
        response.setID(("_"+UUID.randomUUID().toString().replace("-","")));
        response.setDestination(spEndPoint);
        response.setIssuer(getValidIssuer());
        response.setStatus(getStatus());
        response.setIssueInstant(new DateTime());
        if (null != inResponseTo) {
            response.setInResponseTo(inResponseTo);
        }

        Assertion assertion = getValidAssertion(userId, inResponseTo, spEndPoint);
        response.getAssertions().add(assertion);
        
        Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
        Signer.signObject(assertion.getSignature());

        return response;
    }
	
	private Status getStatus() {
        StatusCode statusCode = (StatusCode) Configuration.getBuilderFactory()
                .getBuilder(StatusCode.DEFAULT_ELEMENT_NAME)
                .buildObject(StatusCode.DEFAULT_ELEMENT_NAME);    	
        statusCode.setValue(StatusCode.SUCCESS_URI);
        Status status = (Status) Configuration.getBuilderFactory()
                .getBuilder(Status.DEFAULT_ELEMENT_NAME)
                .buildObject(Status.DEFAULT_ELEMENT_NAME);    	
        status.setStatusCode(statusCode);
        return status;
	}

	private Conditions getConditions() {
        Conditions conditions = (Conditions) Configuration.getBuilderFactory()
                .getBuilder(Conditions.DEFAULT_ELEMENT_NAME)
                .buildObject(Conditions.DEFAULT_ELEMENT_NAME);    	
        DateTime expire = new DateTime().plusHours(3);
        conditions.setNotBefore(new DateTime());
        conditions.setNotOnOrAfter(expire);
        conditions.getAudienceRestrictions().add(getAudienceRestriction(AUDIENCE));
        return conditions;
	}
	
    private AudienceRestriction getAudienceRestriction(String... audienceURI) {
    	AudienceRestriction audienceRestriction = (AudienceRestriction) Configuration.getBuilderFactory()
                .getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME)
                .buildObject(AudienceRestriction.DEFAULT_ELEMENT_NAME);    	
    	Audience audience = (Audience) Configuration.getBuilderFactory()
                .getBuilder(Audience.DEFAULT_ELEMENT_NAME)
                .buildObject(Audience.DEFAULT_ELEMENT_NAME);    	
        for (String uri : audienceURI) {
            audience.setAudienceURI(uri);
            audienceRestriction.getAudiences().add(audience);
        }
        return audienceRestriction;
    }

    
    private AuthnContext getValidAuthContext() {
    	AuthnContext context = (AuthnContext) Configuration.getBuilderFactory()
                .getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME)
                .buildObject(AuthnContext.DEFAULT_ELEMENT_NAME);    	
    	AuthnContextClassRef classRef = (AuthnContextClassRef) Configuration.getBuilderFactory()
                .getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME)
                .buildObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);    	
    	classRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
    	context.setAuthnContextClassRef(classRef);
        return context;
    }
    
    private AuthnStatement getValidAuthStatement() {
    	AuthnStatement statement = (AuthnStatement) Configuration.getBuilderFactory()
                .getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME)
                .buildObject(AuthnStatement.DEFAULT_ELEMENT_NAME);    	
        DateTime dateNow = new DateTime();
        statement.setAuthnInstant(dateNow);
        DateTime expire = new DateTime().plusHours(3);
        statement.setSessionNotOnOrAfter(expire);
        statement.setSessionIndex(UUID.randomUUID().toString().replace("-",""));
        statement.setAuthnContext(getValidAuthContext());
        return statement;
    }
    
    private SubjectConfirmation getBearerConfirmation(String inResponseTo, String spEndPoint) {
    	SubjectConfirmation subjectConfirmation = (SubjectConfirmation) Configuration.getBuilderFactory()
                .getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME)
                .buildObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);    	

    	SubjectConfirmationData subjectConfirmationData = (SubjectConfirmationData) Configuration.getBuilderFactory()
                .getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME)
                .buildObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);    	

        subjectConfirmationData.setNotOnOrAfter(new DateTime().plusHours(1));
        if (null != inResponseTo) {
        	subjectConfirmationData.setInResponseTo(inResponseTo);
        }

        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        //Set the service provider endpoint (to receive AuthnResponse
        subjectConfirmationData.setRecipient(spEndPoint);
        return subjectConfirmation;
    }
    
    private Signature getSignature(Credential credential, KeyInfoGenerator keyInfoGenerator) throws SecurityException, SignatureException, MarshallingException {
    	Signature signature = (Signature) Configuration.getBuilderFactory()
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA); 
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signature.setSigningCredential(credential);
        signature.setKeyInfo(keyInfoGenerator.generate(credential));
        return signature;
    }

    private Issuer getValidIssuer() {
    	Issuer issuer = (Issuer) Configuration.getBuilderFactory()
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME)
                .buildObject(Issuer.DEFAULT_ELEMENT_NAME);    	
        issuer.setValue(IDP_ISSUER);
        return issuer;
    }
    
    private Assertion getValidAssertion(String userId, String inResponseTo, String spEndPoint) throws Exception {
    	Assertion assertion = (Assertion) Configuration.getBuilderFactory()
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME)
                .buildObject(Assertion.DEFAULT_ELEMENT_NAME);    	
    	Subject subject = (Subject) Configuration.getBuilderFactory()
                .getBuilder(Subject.DEFAULT_ELEMENT_NAME)
                .buildObject(Subject.DEFAULT_ELEMENT_NAME);    	
    	NameID nameID = (NameID) Configuration.getBuilderFactory()
                .getBuilder(NameID.DEFAULT_ELEMENT_NAME)
                .buildObject(NameID.DEFAULT_ELEMENT_NAME);    	

    	assertion.setIssueInstant(new DateTime());
        assertion.setID("_"+UUID.randomUUID().toString().replace("-",""));
        assertion.setIssuer(getValidIssuer());
        Credential credential = keyManager().getDefaultCredential();
        SecurityConfiguration secConfiguration = Configuration.getGlobalSecurityConfiguration(); 
        KeyInfoGenerator keyInfoGenerator = SecurityHelper.getKeyInfoGenerator(credential, secConfiguration, null);

        nameID.setFormat(NameIDType.EMAIL);
        nameID.setNameQualifier(IDP_ISSUER);
        nameID.setValue(userId);
        
        subject.setNameID(nameID);
        subject.getSubjectConfirmations().add(getBearerConfirmation(inResponseTo, spEndPoint));
        assertion.setSubject(subject);

        assertion.setSignature(getSignature(credential,keyInfoGenerator));
        assertion.getAuthnStatements().add(getValidAuthStatement());
        assertion.setConditions(getConditions());
        
        return assertion;
    }

    public AuthnRequest decodeSamlRequest(String base64EncodedRequest) throws Exception{
    	System.out.println(base64EncodedRequest);
//    	String a = "nVNLb9swDP4rhu6OH%2FUKh4gDpCmGBeg2I%2FF62KWQZXrRIEueKK%2FZv5%2FsJEWApTnsJID8xO8hakG8Uz2sBrfXW%2Fw1ILng0ClNMDUKNlgNhpMk0LxDAidgt%2Fr8BOksht4aZ4RRLNg8Fuyl5vM6wzsMRXtXh1ka52GdZ2l4n2ZJNp%2B3cctzFjyjJWl0wfwEf5FowI0mx7XzpTi5D%2BMPYZJVaQrpHJL4OwvKE82D1I3UP25rqo8ggk9VVYbl113FghURWudJ10bT0KHdof0tBX7bPhVs71wPUaSM4GpvyEEe53EkjsjZT%2BrZcjFmAZNUe5HObSH8TMqW1ym8UDyMBIvoYv6RrIcvfuDmsTRKij%2FBR2M77t7nS2bJVJFN2E5QGDT1KGQrsfH%2BlTKva4vcYcGcHdBbiv6lOVOf9gCbaSt8Zg4PLlibrudW0vh0eODCnXO5RK2Vt73F9n9SugkTIMbRvlz649XYZtwKFF5lZbk3a6w75XhNz5vfq97eupffYPkX";
    	byte[] request = Base64.decode(base64EncodedRequest);
    	Inflater inflater = new Inflater(true);
    	inflater.setInput(request);
    	byte[] xmlMessageBytes = new byte[5000];
    	int resultLength = inflater.inflate(xmlMessageBytes);
    	if (!inflater.finished()) {
    	    throw new RuntimeException("didn't allocate enough space to hold "
    	            + "decompressed data");
    	}
    	inflater.end();      
	    DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
	    documentBuilderFactory.setNamespaceAware(true);
	    DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();

	    Document document = docBuilder.parse(new ByteArrayInputStream(xmlMessageBytes, 0, resultLength));
	    Element element = document.getDocumentElement();

	    UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
	    Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
	    XMLObject requestXmlObj = unmarshaller.unmarshall(element);
	    AuthnRequest authnRequest = (AuthnRequest) requestXmlObj;
	    
    	System.out.println(authnRequest.getID());
       	System.out.println(authnRequest.getAssertionConsumerServiceURL());
       	return authnRequest;
    }
    
}
