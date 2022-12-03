import java.nio.ByteBuffer;
import java.security.*;

public class Peer {

    KeyPair keyPair;

    public Peer() {
        try {
            SecureRandom secureRandom = new SecureRandom();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048, secureRandom);
            keyPair = kpg.generateKeyPair();
        }
        catch (Exception e) {
            System.out.println("Creating peer: " + e);
        }
    }

    public byte[] signTransaction(PublicKey receiverPK, byte[] prevTxId) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(keyPair.getPrivate());
            byte[] PK = receiverPK.getEncoded();

            ByteBuffer buffer = ByteBuffer.allocate(PK.length+32);
            buffer.put(PK);
            buffer.put(prevTxId);
            signature.update(buffer.array());
            return signature.sign();
        }
        catch (Exception e) {
            System.out.println("signTransaction: " + e);
            return null;
        }
    }

}
