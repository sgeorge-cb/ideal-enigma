# cb-client
An experiment project to test out Authentication through SAML2 using spring. 
This project demonstrates the use of IdP initiated SAML2 without the use of an actual IdP.

### Pre-requisites
1. Set up the sample OneLogin SP by cloning and following instructions on https://github.com/onelogin/java-saml.git
2. There will be 2 projects - **_java-saml_** and **_java-saml-sample_**
3. Clone the ideal-enigma project and set it up as a gradle project
4. Make sure ideal-enigma is configured to use the mongo repository that has the CB Profile Collection with user information
5. Copy the public key from **project: _/ideal-enigma/blob/master/src/main/resources/saml/cb2056.pem_** to  **project:   _/java-saml-sample/src/main/webapp/consume.jsp_**




