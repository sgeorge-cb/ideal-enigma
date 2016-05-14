package org.caringbridge.client.security.services;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
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
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.MarshallingException;
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
import org.w3c.dom.Element;

@Service
public class SAMLGeneratorService{

	private static String SP_ENDPOINT = "http://localhost:8080/consume.jsp";
	private static String IDP_ISSUER = "http://www.caringbridge.org";
	
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

	
	public String getSamlResponse(String userId) throws Exception {
		Response response = generateValidSAMLResponse(userId);
    	ResponseMarshaller marshaller = new ResponseMarshaller();
    	debugprintSAMLObject(response); //Just for debugging
        Element element = marshaller.marshall(response);
        return Base64.encode(XMLHelper.nodeToString(element).getBytes());
	}

	public Response generateValidSAMLResponse(String userId) throws ConfigurationException, SecurityException, MessageEncodingException, SignatureException, MarshallingException {
    	DefaultBootstrap.bootstrap();
    	Response response = (Response) Configuration.getBuilderFactory()
                .getBuilder(Response.DEFAULT_ELEMENT_NAME)
                .buildObject(Response.DEFAULT_ELEMENT_NAME);    	
        response.setID(("_"+UUID.randomUUID().toString().replace("-","")));
        response.setDestination(SP_ENDPOINT);
        response.setIssuer(getValidIssuer());
        StatusCode statusCode = (StatusCode) Configuration.getBuilderFactory()
                .getBuilder(StatusCode.DEFAULT_ELEMENT_NAME)
                .buildObject(StatusCode.DEFAULT_ELEMENT_NAME);    	
        statusCode.setValue(StatusCode.SUCCESS_URI);
        Status status = (Status) Configuration.getBuilderFactory()
                .getBuilder(Status.DEFAULT_ELEMENT_NAME)
                .buildObject(Status.DEFAULT_ELEMENT_NAME);    	
        status.setStatusCode(statusCode);
        response.setStatus(status);
        response.setIssueInstant(new DateTime());

        Assertion assertion = getValidAssertion(userId);
        assertion.getSubject().getSubjectConfirmations().add(getBearerConfirmation());
        assertion.getAuthnStatements().add(getValidAuthStatement());

        Conditions conditions = (Conditions) Configuration.getBuilderFactory()
                .getBuilder(Conditions.DEFAULT_ELEMENT_NAME)
                .buildObject(Conditions.DEFAULT_ELEMENT_NAME);    	
        DateTime expire = new DateTime().plusHours(3);
        conditions.setNotBefore(new DateTime());
        conditions.setNotOnOrAfter(expire);
        conditions.getAudienceRestrictions().add(getAudienceRestriction("com:sample:spring:sp"));
        assertion.setConditions(conditions);

        response.getAssertions().add(assertion);
        
        try {
            Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
        } catch (MarshallingException e) {
            e.printStackTrace();
        }

        try {
            Signer.signObject(assertion.getSignature());
        } catch (SignatureException e) {
            e.printStackTrace();
        }


        return response;
    }
    
    protected AudienceRestriction getAudienceRestriction(String... audienceURI) {
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

    
    public AuthnContext getValidAuthContext() {
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
    public AuthnStatement getValidAuthStatement() {
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

    public SubjectConfirmation getBearerConfirmation() {
    	SubjectConfirmation subjectConfirmation = (SubjectConfirmation) Configuration.getBuilderFactory()
                .getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME)
                .buildObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);    	

    	SubjectConfirmationData subjectConfirmationData = (SubjectConfirmationData) Configuration.getBuilderFactory()
                .getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME)
                .buildObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);    	

        subjectConfirmationData.setNotOnOrAfter(new DateTime().plusHours(1));

        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        //Set the service provider endpoint (to receive AuthnResponse
        subjectConfirmationData.setRecipient(SP_ENDPOINT);
       return subjectConfirmation;
    }
    
    public Signature getSignature(Credential credential, KeyInfoGenerator keyInfoGenerator) throws SecurityException, SignatureException, MarshallingException {
    	Signature signature = (Signature) Configuration.getBuilderFactory()
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA); 
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signature.setSigningCredential(credential);
        signature.setKeyInfo(keyInfoGenerator.generate(credential));
        return signature;
    }

    public Issuer getValidIssuer() {
    	Issuer issuer = (Issuer) Configuration.getBuilderFactory()
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME)
                .buildObject(Issuer.DEFAULT_ELEMENT_NAME);    	
        issuer.setValue(IDP_ISSUER);
        return issuer;
        
    }
    
    
    public Assertion getValidAssertion(String userId) throws SecurityException, MessageEncodingException, SignatureException, MarshallingException {
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

        assertion.setSubject(subject);
        Signature signature = getSignature(credential,keyInfoGenerator);
        assertion.setSignature(signature);

        return assertion;
    }

    public static void loadCertificate(String certificate, boolean isBase64) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        byte[] cert = certificate.getBytes();
        if (isBase64) {
            cert = Base64.decode(cert);
        }
        ByteArrayInputStream bais = new ByteArrayInputStream(cert);
        certFactory.generateCertificate(bais);
    }	
}
