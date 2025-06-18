import java.io.FileInputStream;
import java.io.IOException;
import java.util.Base64;
import java.io.File;

public class FileDigest {
    public static void main(String[] args) {
    	//Checking whether file exists or not
    	if (args.length != 1) {
    		System.out.println("No file detected");
    		return;
    	}
    	
    	String filename = args[0];
    	File file = new File(filename);
 
    	
    	try(FileInputStream Fileinput = new FileInputStream(file)){
    		HandshakeDigest handshake = new HandshakeDigest();
    		byte [] buffer = new byte[1024];
    		int bytesRead;
    		
    		//Read file data and update digest
    			
    		while((bytesRead = Fileinput.read(buffer)) != -1 ) {
    			byte[] actualBytes = new byte[bytesRead];
    			System.arraycopy(buffer,0,actualBytes,0,bytesRead);
    			handshake.update(actualBytes);
    		}
    		byte hash [] = handshake.digest();
    		String base64Hash = Base64.getEncoder().encodeToString(hash);
    		
    		System.out.println(base64Hash);
    	//https://stackoverflow.com/questions/42486709/creating-a-base64-encoded-sha-256-hash-in-java	
    		
    	}catch (IOException e) {
    		System.out.println("Error Reading file" + e.getMessage());
    	}
}
}