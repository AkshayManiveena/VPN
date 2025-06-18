import java.io.InputStream;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
/*
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */
public class HandshakeCertificate {
	
	private X509Certificate certificate;

    /*
     * Constructor to create a certificate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     */
    HandshakeCertificate(InputStream instream)throws CertificateException {
    	CertificateFactory factory = CertificateFactory.getInstance("X.509");
    	this.certificate = (X509Certificate) factory.generateCertificate(instream);
    }

    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     */
    HandshakeCertificate(byte[] certbytes) throws CertificateException{
    	CertificateFactory factory = CertificateFactory.getInstance("X.509");
    	this.certificate = (X509Certificate) factory.generateCertificate(new java.io.ByteArrayInputStream(certbytes));
    	
    }

    /*
     * Return the encoded representation of certificate as a byte array
     */
    public byte[] getBytes()throws CertificateException {
        return this.certificate.getEncoded();
    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() throws CertificateException{
        return this.certificate;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     */
    public void verify(HandshakeCertificate cacert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
    	this.certificate.verify(cacert.getCertificate().getPublicKey());
    }

    /*
     * Return CN (Common Name) of subject
     */
    public String getCN() {
    	try {
    		String distinguishedName = this.certificate.getSubjectX500Principal().getName();
    		LdapName ldapName = new LdapName(distinguishedName);
    		for (Rdn rdn:ldapName.getRdns()) {
    			if(rdn.getType().equalsIgnoreCase("CN")) {
    				return rdn.getValue().toString();
    			}
    		}
        }catch (Exception e) {
        	e.printStackTrace();
        }
    	return null;
    }
    // https://www.baeldung.com/java-extract-common-name-x509-certificate
    //Used ldap method for extracting CN and email address from certificate
    //https://docs.oracle.com/javase/8/docs/api/javax/security/auth/x500/X500Principal.html

    /*
     * return email address of subject
     */
    public String getEmail() {
    	X500Principal principal = certificate.getSubjectX500Principal();
    	
    	try {

    		LdapName ldapName = new LdapName(principal.toString());
    		for (Rdn rdn:ldapName.getRdns()) {
    			if(rdn.getType().equalsIgnoreCase("emailaddress")) {
    				return rdn.getValue().toString();
    			}
    		}
    		return principal.toString();
        }catch (Exception e) {
        	e.printStackTrace();
        }
    	return null;
       
}
}