import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
public class SessionKey {
	private SecretKey secret;

	public SessionKey(Integer Keylength)throws NoSuchAlgorithmException  {
		//Random key with length , keylength(128 or 256)
		
			KeyGenerator Keygen = KeyGenerator.getInstance("AES");
			Keygen.init(Keylength);
			secret = Keygen.generateKey();


	}
	
	public SessionKey(byte[] keybytes) {
		//Sessionkey from existing byte array
		
		secret = new SecretKeySpec(keybytes,0,keybytes.length,"AES");
	}
	
	public String encodeKey(){
		
		return Base64.getEncoder().withoutPadding().encodeToString(secret.getEncoded());
	}
	public SecretKey getSecretKey() {
			
		return secret;
	}
	public byte[] getKeyBytes() {
		//Encryption	
		return secret.getEncoded();
	}
	public static void main(String[] args) {
		//Printing to check all the return parameters
		try {
			SessionKey sessionKey = new SessionKey(128);
			System.out.println("Encoded Key:"+ sessionKey.encodeKey());
			System.out.println("Secretkey:"+ sessionKey.getSecretKey());
			System.out.println("Keybytes:"+ sessionKey.getKeyBytes());
			}catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
			

	}
}
