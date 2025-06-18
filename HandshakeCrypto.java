import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;


public class HandshakeCrypto {
	private Key key;

	/*
	 * Constructor to create an instance for encryption/decryption with a public key.
	 * The public key is given as a X509 certificate.
	 */
	public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {
		try {
			X509Certificate certificate = handshakeCertificate.getCertificate();
			this.key = certificate.getPublicKey();
		} catch (Exception e) {
			throw new IllegalArgumentException("PublicKey not Initialized",e);
		}
	}

	/*
	 * Constructor to create an instance for encryption/decryption with a private key.
	 * The private key is given as a byte array in PKCS8/DER format.
	 */
	//https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
	public HandshakeCrypto(byte[] keybytes) {
		try {
			KeyFactory keyfactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec encodedspec = new PKCS8EncodedKeySpec(keybytes);
			this.key = keyfactory.generatePrivate(encodedspec);
		}catch(Exception e) {
			throw new IllegalArgumentException("PrivateKey not Initialized");
		}
	}

	/*
	 * Decrypt byte array with the key, return result as a byte array
	 */
    public byte[] decrypt(byte[] ciphertext) {
    	try {
    		Cipher cipher = Cipher.getInstance("RSA");
    		cipher.init(Cipher.DECRYPT_MODE,key);
    		return cipher.doFinal(ciphertext);
    	}catch (Exception e) {
    		throw new RuntimeException("Decryption failed",e);
    	}
    }
    //https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html
	/*
	 * Encrypt byte array with the key, return result as a byte array
	 */
    public byte [] encrypt(byte[] plaintext) {
    	try {
    		Cipher cipher = Cipher.getInstance("RSA");
    		cipher.init(Cipher.ENCRYPT_MODE, key);
    		return cipher.doFinal(plaintext);
    	}catch(Exception e) {
    		throw new RuntimeException("Encryption Failed",e);
    	}
    	
    }
}