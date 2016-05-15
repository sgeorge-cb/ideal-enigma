# cb-client
An experiment project to test out Authentication through SAML2 using spring. 
This project demonstrates the use of IdP initiated SAML2 without the use of an actual IdP.

### Setup
1. Clone and set up ideal-enigma as a gradle project
2. Make sure ideal-enigma is configured to use the mongo repository that has the CB Profile Collection with user information
3. Run as Spring Boot application
4. Access the application at http://localhost:11002/login
5. Enter CB userid and password. If successful, user will reach home page.
6. Click on the "IDP Initiated" or "SP Initiated" button. 
7. The user will be logged into the SP application as the CB user.

### Pre-requisite (There needs to be a SAML2 Service Provider that we can test against)
1. For this demo we can use the open source OneLogin SP by cloning and following instructions on https://github.com/onelogin/java-saml.git
2. java-saml has 2 projects - **_java-saml_** and **_java-saml-sample_**
3. Copy the public key from **project: _/ideal-enigma/src/main/resources/saml/cb2056.pem_** to  **project:   _/java-saml-sample/src/main/webapp/consume.jsp_**
4. Run the application. 
5. Make sure ideal-enigma posts the SAML AuthResponse to http://localhost:8080/consume.jsp (which is the SP Url)
6. Note: If both the SP and the application have the same domain (in this example - localhost), the JSESSIONID of the application gets overwritten when the SAML request/response is exchanged. This will cause the user to have to login to the original application again. To avoid this, we can set up different domains for each application. Or we can use persistent cookies to store information.




