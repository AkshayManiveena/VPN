import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;


public class SessionCipher {

    /*
     * Constructor to create a SessionCipher from a SessionKey. The IV is
     * created automatically.
     */
	
	private SessionKey sessionkey;
	private Cipher cipher;
	private IvParameterSpec ivParameterSpec;
    public SessionCipher(SessionKey key) throws Exception{
    	 try {
    		this.sessionkey = key;
    		this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
    	
    		byte[] iv = new byte [cipher.getBlockSize()];    //AES block size is 16 bytes
    		new SecureRandom().nextBytes(iv);
    		this.ivParameterSpec = new IvParameterSpec(iv);
    	} catch (Exception e) {
    		throw new RuntimeException ("Erros with SessionCipher from Sessionkey :" + e.getMessage(),e);
    	}
    }
 // https://stackoverflow.com/questions/11912582/initialization-vector-iv-update-frequency

    /*
     * Constructor to create a SessionCipher from a SessionKey and an IV,
     * given as a byte array.
     */

    public SessionCipher(SessionKey key, byte[] ivbytes)throws Exception {
    	try {
    		this.sessionkey = key;
    		this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
    		this.ivParameterSpec = new IvParameterSpec(ivbytes);
    	}catch(Exception e) {
    		throw new RuntimeException ("Erros with SessionCipher byte array :" + e.getMessage(),e);
    	}
    }

    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {
        return sessionkey;
    }

    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {
        return ivParameterSpec.getIV();
    }

    /*
     * Attach OutputStream to which encrypted data will be written.
     * Return result as a CipherOutputStream instance.
     */
    public CipherOutputStream openEncryptedOutputStream(OutputStream os) {
        try {
        	cipher.init(Cipher.ENCRYPT_MODE, sessionkey.getSecretKey(),ivParameterSpec);
       
        	return new CipherOutputStream(os,cipher);
        }catch(Exception e) {
    		throw new RuntimeException ("Error with ENCRYPT MODE :" + e.getMessage(),e);
    }
    }

    /*
     * Attach InputStream from which decrypted data will be read.
     * Return result as a CipherInputStream instance.
     */

    public CipherInputStream openDecryptedInputStream(InputStream inputstream){
    	try {
        	cipher.init(Cipher.DECRYPT_MODE, sessionkey.getSecretKey(),ivParameterSpec);
        	return new CipherInputStream(inputstream,cipher);
        }catch(Exception e) {
    		throw new RuntimeException ("Error with DECRYPT MODE :" + e.getMessage(),e); 
    }
    	// https://www.baeldung.com/java-cipher-input-output-stream
}

}