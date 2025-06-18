import java.net.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.text.SimpleDateFormat;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import java.util.Arrays;
import java.util.Base64;

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        System.err.println("    --host=<hostname>");
        System.err.println("    --port=<portnumber>");
        System.err.println("    --usercert=<client certificate>");
        System.err.println("    --cacert=<CA certificate>");
        System.err.println("    --key=<client private key>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
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

    /*
     * Main program: connects to the server, performs the handshake, and starts secure communication
     */
    public static void main( String[] args) {
        try {
            // Step 1: Parse arguments from command line
            parseArgs(args);

            // Step 2: Load the certificates
            HandshakeCertificate clientCert = new HandshakeCertificate(new FileInputStream(arguments.get("usercert")));
            HandshakeCertificate caCert = new HandshakeCertificate(new FileInputStream(arguments.get("cacert")));

            // Step 3: Establish connection
            Socket socket = establishConnection(arguments.get("host"), Integer.parseInt(arguments.get("port")));

            // Step 4: Perform the handshake process
            performHandshake(socket, clientCert, caCert);

            // Step 5: Start secure communication
            startSecureConnection(socket);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    // Function to establish socket connection
    private static Socket establishConnection(String host, int port) throws IOException {
        Socket socket = new Socket(host, port);
        System.out.println("Connection established with " + host + " on port " + port);
        return socket;
    }

    // Function to perform the handshake with the server
    private static void performHandshake(Socket socket, HandshakeCertificate clientCert, HandshakeCertificate caCert) throws Exception {
        sendClientHello(socket, clientCert);
        HandshakeMessage serverHello = receiveAndValidateServerHello(socket, caCert);
        sendSessionMessage(socket, serverHello, clientCert);
        receiveAndSendClientFinished(socket, serverHello);
    }

    // Send CLIENTHELLO message
    private static void sendClientHello(Socket socket, HandshakeCertificate clientCert) throws Exception {
        HandshakeMessage clientHello = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        clientHello.putParameter("Certificate", Base64.getEncoder().encodeToString(clientCert.getBytes()));
        clientHello.send(socket);
        System.out.println("Sent CLIENTHELLO");
    }

    // Receive and validate SERVERHELLO message
    private static HandshakeMessage receiveAndValidateServerHello(Socket socket, HandshakeCertificate caCert) throws Exception {
        HandshakeMessage serverHello = HandshakeMessage.recv(socket);
        HandshakeCertificate serverCert = new HandshakeCertificate(Base64.getDecoder().decode(serverHello.getParameter("Certificate")));
        serverCert.verify(caCert);
        System.out.println("SERVERHELLO received and verified.");
        return serverHello;
    }

    // Send SESSION message (with encrypted session key and IV)
    private static void sendSessionMessage(Socket socket, HandshakeMessage serverHello, HandshakeCertificate clientCert) throws Exception {
        SessionKey sessionKey = new SessionKey(128);  // 128-bit AES key
        SessionCipher sessionCipher = new SessionCipher(sessionKey);
        byte[] sessionKeyBytes = sessionKey.getKeyBytes();
        byte[] sessionIV = sessionCipher.getIVBytes();

        HandshakeCrypto serverPublic = new HandshakeCrypto(new HandshakeCertificate(new FileInputStream(arguments.get("cacert"))));
        String encryptedSessionKey = Base64.getEncoder().encodeToString(serverPublic.encrypt(sessionKeyBytes));
        String encryptedSessionIV = Base64.getEncoder().encodeToString(serverPublic.encrypt(sessionIV));

        HandshakeMessage sessionMessage = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
        sessionMessage.putParameter("SessionKey", encryptedSessionKey);
        sessionMessage.putParameter("SessionIV", encryptedSessionIV);
        sessionMessage.send(socket);
        System.out.println("SESSION message sent.");
    }

    // Receive the SERVERFINISHED message and send the CLIENTFINISHED message
    private static void receiveAndSendClientFinished(Socket socket, HandshakeMessage serverHello) throws Exception {
        HandshakeMessage serverFinished = HandshakeMessage.recv(socket);
        byte[] serverSignature = verifyServerSignature(serverFinished, serverHello);

        HandshakeCrypto clientPrivateKey = new HandshakeCrypto(new FileInputStream(arguments.get("key")).readAllBytes());
        HandshakeMessage clientFinished = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);

        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(System.currentTimeMillis());
        clientFinished.putParameter("Signature", Base64.getEncoder().encodeToString(clientPrivateKey.encrypt(serverSignature)));
        clientFinished.putParameter("TimeStamp", Base64.getEncoder().encodeToString(clientPrivateKey.encrypt(timestamp.getBytes(StandardCharsets.UTF_8))));
        clientFinished.send(socket);
        System.out.println("CLIENTFINISHED sent.");
    }

    // Verifying server's signature
    private static byte[] verifyServerSignature(HandshakeMessage serverFinished, HandshakeMessage serverHello) throws Exception {
        HandshakeCrypto serverPublic = new HandshakeCrypto(new HandshakeCertificate(Base64.getDecoder().decode(serverFinished.getParameter("Certificate"))));
        byte[] serverSignature = serverPublic.decrypt(Base64.getDecoder().decode(serverFinished.getParameter("Signature")));
        HandshakeDigest verifyDigest = new HandshakeDigest();
        verifyDigest.update(serverHello.getBytes());
        if (!Arrays.equals(verifyDigest.digest(), serverSignature)) {
            throw new SecurityException("SERVERFINISHED digest mismatch.");
        }
        return verifyDigest.digest();
    }

    // Function to start secure communication after the handshake
    private static void startSecureConnection(Socket socket) throws Exception {
        System.out.println("Starting secure connection");
        SessionKey sessionKey = new SessionKey(128);  // Assuming sessionKey initialization
        SessionCipher sessionCipher = new SessionCipher(sessionKey);

        Forwarder.forwardStreams(System.in, System.out,
                sessionCipher.openDecryptedInputStream(socket.getInputStream()),
                sessionCipher.openEncryptedOutputStream(socket.getOutputStream()), socket);
    }
}
