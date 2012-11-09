import SAML
import time
from django.http import HttpResponse

#@login_required
def SAML_assert(request):
	# Enable SAML logging if needed for debugging
	# SAML.log(logging.DEBUG, "PySAML.log")

	# The subject of the assertion. Usually an e-mail address or username.
	subject = SAML.Subject(request.user.email,"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")

	# The authentication statement which is how the person is proving he really is that person. Usually a password.
	authStatement = SAML.AuthenticationStatement(subject,"urn:oasis:names:tc:SAML:1.0:am:password",None)

	# Create a conditions timeframe of 5 minutes (period in which assertion is valid)
	notBefore = time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
	notOnOrAfter = time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(time.time() + 5))
	conditions = SAML.Conditions(notBefore, notOnOrAfter)

	# Create the actual assertion
	assertion = SAML.Assertion(authStatement, "Test Issuer", conditions)

	# At this point I have an assertion. To sign the assertion I need to put it into a SAML response
	# object.

	# Open up private key file
	privateKeyFile = open("keys/private-key.pem","r")
	privatekey = privateKeyFile.read()

	# Open up the certificate
	certificateFile = open("keys/certificate.pem","r")
	certificate = certificateFile.read()

	# Sign with the private key but also include the certificate in the SAML response
	response = SAML.Response(assertion, privatekey, certificate)
	return HttpResponse(response,  mimetype='text/xml')
