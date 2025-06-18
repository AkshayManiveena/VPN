import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Base64;

import javax.crypto.spec.IvParameterSpec;

import java.util.Arrays;

public class NetPipeServer {
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
    private static Arguments arguments;
    
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        System.err.println("    --port=<portnumber>");
        System.err.println("    --usercert=<server certificate>");
        System.err.println("    --cacert=<CA certificate>");
        System.err.println("    --key=<server private key>");

        System.exit(1);
    }
    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "filename");
        arguments.setArgumentSpec("cacert", "filename");
        arguments.setArgumentSpec("key", "filename");

        try {
            arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }
    public static void main(String[] args) {
        try {
            parseArgs(args);
            int port = Integer.parseInt(arguments.get("port"));
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Server listening on port " + port);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected.");
                handleClient(clientSocket);
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    // Method to handle communication with the client
    private static void handleClient(Socket socket) throws Exception {
    	// Load server and CA certificates
    	
        HandshakeCertificate serverCert = new HandshakeCertificate(new FileInputStream(arguments.get("usercert")));
        HandshakeCertificate caCert = new HandshakeCertificate(new FileInputStream(arguments.get("cacert")));

     // Perform the handshake with the client
        performHandshake(socket, serverCert, caCert);
        startSecureConnection(socket);  //Start secure connection
    }
    
    //Handshake Method
    private static void performHandshake(Socket socket, HandshakeCertificate serverCert, HandshakeCertificate caCert) throws Exception {
    	// Receive client hello message
    	
    	HandshakeMessage clientHello = HandshakeMessage.recv(socket);
    	
    	// Extract and verify client certificate
    	
    	HandshakeCertificate clientCert = new HandshakeCertificate(Base64.getDecoder().decode(clientHello.getParameter("Certificate")));
    	clientCert.verify(caCert); //Verifying CA certificate
        
    	System.out.println("CLIENTHELLO received and verified.");

    	// Send server hello message with server's certificate
    	
        HandshakeMessage serverHello = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
        serverHello.putParameter("Certificate", Base64.getEncoder().encodeToString(serverCert.getBytes()));
        serverHello.send(socket);
        System.out.println("SERVERHELLO sent.");

        // Receive session message containing the encrypted session key and IV
        HandshakeMessage sessionMessage = HandshakeMessage.recv(socket);
        byte[] sessionKeyBytes = decryptParameter(sessionMessage.getParameter("SessionKey"), arguments.get("key"));
        byte[] sessionIV = decryptParameter(sessionMessage.getParameter("SessionIV"), arguments.get("key"));

        // Create session key and cipher for encrypted communication
        SessionKey sessionKey = new SessionKey(sessionKeyBytes);
        SessionCipher sessionCipher = new SessionCipher(sessionKey, sessionIV);

        // Send SERVERFINISHED message with a signature and timestamp
        HandshakeMessage serverFinished = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
        serverFinished.putParameter("Signature", generateSignature(serverHello));
        serverFinished.putParameter("TimeStamp", getCurrentTimeStamp());
        serverFinished.send(socket);
        System.out.println("SERVERFINISHED sent.");

        // Receive CLIENTFINISHED message from the client and verify it
        HandshakeMessage clientFinished = HandshakeMessage.recv(socket);
        verifyClientFinished(clientFinished, clientHello, sessionMessage, clientCert);
        System.out.println("Handshake completed.");
    }
    
    	// Decrypt parameters such as the session key or IV using the server's private key
    private static byte[] decryptParameter(String encodedData, String keyFile) throws Exception {
        HandshakeCrypto privateKey = new HandshakeCrypto(new FileInputStream(keyFile).readAllBytes());
        return privateKey.decrypt(Base64.getDecoder().decode(encodedData));
    }

    	// Generate a digital signature for the message using the server's private key
    private static String generateSignature(HandshakeMessage message) throws Exception {
        HandshakeCrypto privateKey = new HandshakeCrypto(new FileInputStream(arguments.get("key")).readAllBytes());
        HandshakeDigest digest = new HandshakeDigest();
        digest.update(message.getBytes());
        return Base64.getEncoder().encodeToString(privateKey.encrypt(digest.digest()));
    }

    	// Get the current timestamp formatted as a string
    private static String getCurrentTimeStamp() {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(System.currentTimeMillis());
    }

    	// Verify the CLIENTFINISHED message from the client    
    private static void verifyClientFinished(HandshakeMessage clientFinished, HandshakeMessage clientHello, HandshakeMessage sessionMessage, HandshakeCertificate clientCert) throws Exception {
        byte[] signature = Base64.getDecoder().decode(clientFinished.getParameter("Signature"));
        byte[] timestamp = Base64.getDecoder().decode(clientFinished.getParameter("TimeStamp"));

        HandshakeCrypto publicKey = new HandshakeCrypto(clientCert);
        HandshakeDigest digest = new HandshakeDigest();
        digest.update(clientHello.getBytes());
        digest.update(sessionMessage.getBytes());

        if (!Arrays.equals(digest.digest(), publicKey.decrypt(signature))) {
            throw new SecurityException("CLIENTFINISHED signature mismatch.");
        }
        System.out.println("CLIENTFINISHED verified.");
    }
    	// Method to start secure communication using AES encryption after handshake
    private static void startSecureConnection(Socket socket) throws Exception {
        SessionKey sessionKey = new SessionKey(128);
        SessionCipher sessionCipher = new SessionCipher(sessionKey);
        Forwarder.forwardStreams(System.in, System.out, sessionCipher.openDecryptedInputStream(socket.getInputStream()), sessionCipher.openEncryptedOutputStream(socket.getOutputStream()), socket);
    }
}

    
    
    
    
    
    
    
    
    
    
    
   
