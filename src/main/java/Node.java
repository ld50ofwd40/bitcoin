import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;

public class Node {

    int nodeId;
    List<Block> blockchain;
    int prefix = 19; //bitekben
    MessageDigest md;

    public Node(int id) {
        nodeId = id;
        blockchain = new ArrayList<>();
        createBlock(new byte[32]); //genesis block létrehozása csupa 0-s prevBlockHash-sel
    }

    public void createBlock(byte[] prevBlockHash) {
        Block block = new Block(prevBlockHash);
        blockchain.add(block);
    }

    public Block getLastBlock() {
        if (blockchain.isEmpty()) {
            return null;
        }
        else {
            return blockchain.get(blockchain.size() - 1);
        }
    }

    public Transaction getLastTransaction() {
        if (getLastBlock() == null) {
            return null;
        }
        else if (getLastBlock().transactions.isEmpty()) {
            return null;
        }
        else {
            return getLastBlock().transactions.get(getLastBlock().transactions.size() - 1);
        }
    }

    public void addTransaction(PublicKey receiverPK, byte[] digitalSignature, byte[] prevTxId) {
        blockchain.get(blockchain.size() - 1).addTransaction(receiverPK, digitalSignature, prevTxId);
    }

    public boolean mineBlock(Block block) {
        int nonce = Integer.MAX_VALUE - 100000;
        boolean mined;
        int leadingZeroes;
        do {
            mined = false;
            byte[] b = calculateHash(block.provideBytesForHashing(nonce));
            leadingZeroes = 256;
            for (int i = 0; i < 256; i++) {
                if (((b[i / 8] << (i % 8)) & 128) != 0) {
                    leadingZeroes = i;
                    break;
                }
            }
            if (leadingZeroes >= prefix) {
                mined = true;
            }
            if (mined) {
                System.out.println("MINED block hash: " + toHexa(b));
                break;
            }
        } while (nonce++ < Integer.MAX_VALUE);
        return mined;
    }

    public byte[] calculateHash(byte[] bytes) {
        byte[] digest = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
            digest = md.digest(bytes);
            md.reset();
        } catch (Exception e) {
            System.out.println("calculateHash: " + e);
        }
        return digest;
    }

    public boolean verifyBlockTransactions(int height) {
        boolean verified = false;
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            for (int i = 1; i < blockchain.get(height).transactions.size(); i++){

                PublicKey prevTxPubkey = blockchain.get(height).transactions.get(i - 1).getOwnerPK();
                byte[] prevTxId = blockchain.get(height).transactions.get(i).getPrevTxId();
                byte[] txPubkey = blockchain.get(height).transactions.get(i).getOwnerPK().getEncoded();
                byte[] txDigitalSignature = blockchain.get(height).transactions.get(i).getDigitalSignature();

                signature.initVerify(prevTxPubkey);

                ByteBuffer buffer = ByteBuffer.allocate(prevTxId.length + txPubkey.length);
                buffer.put(txPubkey);
                buffer.put(prevTxId);
                signature.update(buffer.array());

                verified = signature.verify(txDigitalSignature);

                if (!verified) {
                    break;
                }
            }
            return verified;
        }
        catch(Exception e) {
            System.out.println("verifyBlockTransactions: " + e);
            return false;
        }
    }

    public static String toHexa(byte[] bytes) {
        StringBuilder s = new StringBuilder();
        for (byte b : bytes) {
            s.append(String.format("%02X", b));
        }
        return s.toString().toLowerCase();
    }
}
