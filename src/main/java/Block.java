import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class Block {
    Date timeStamp;
    int nonce;
    byte[] merkleRoot;
    byte[] prevBlockHash;
    List<Transaction> transactions;
    MessageDigest md;

    public Block(byte[] prevBlockHash) {
        transactions = new ArrayList<>();
        timeStamp = new Date();
        nonce = 0;
        merkleRoot = new byte[32];
        this.prevBlockHash = prevBlockHash;
    }

    public List<byte[]> getTxHashes() {
        List<byte[]> txHashes = new ArrayList<>();
        for (Transaction t : transactions) {
            txHashes.add(t.getTxId());
        }
        return txHashes;
    }

    public byte[] provideBytesForHashing(int nonce) {
        this.nonce = nonce;
        ByteBuffer buffer = ByteBuffer.allocate(8+4+32+32);
        buffer.putLong(timeStamp.getTime());
        buffer.putInt(this.nonce);
        buffer.put(merkleRoot);
        buffer.put(prevBlockHash);
        return buffer.array();
    }

    public void addTransaction(PublicKey receiverPK, byte[] digitalSignature, byte[] prevTxId) {
        Transaction transaction = new Transaction();
        transaction.setDigitalSignature(digitalSignature);
        transaction.setOwnerPK(receiverPK);
        transaction.setPrevTxId(prevTxId);
        byte[] ownerPKBytes = receiverPK.getEncoded();
        ByteBuffer buffer =
                ByteBuffer.allocate(ownerPKBytes.length +
                        prevTxId.length +
                        digitalSignature.length);
        buffer.put(ownerPKBytes);
        buffer.put(transaction.getPrevTxId());
        buffer.put(transaction.getDigitalSignature());

        transaction.setTxId(calculateHash(buffer.array()));

        transactions.add(transaction);
        System.out.println("New transaction has been added. Building Merkle tree. (number of transactions: " + transactions.size() + ")");
        for (byte[] h : getTxHashes()) {
            System.out.print(toHexa(h) + " ");
        }
        System.out.println();
        merkleRoot = buildTree(getTxHashes());
        System.out.println();
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

    public byte[] buildTree(List<byte[]> txHashes) {
        List<byte[]> newTxHashes = new ArrayList<>();
        if (txHashes.size() == 1) {
            return txHashes.get(0);
        } else {
            try {
                md = MessageDigest.getInstance("SHA-256");
                int i = 0;
                while (i < txHashes.size() - 1) {
                    newTxHashes.add(md.digest(concatBytes(txHashes.get(i), txHashes.get(i + 1))));
                    i += 2;
                }
                if (i < txHashes.size()) {
                    newTxHashes.add(md.digest(concatBytes(txHashes.get(i), txHashes.get(i))));
                }
            } catch (Exception e) {
                System.out.println("buildTree: " + e);
            }
            if (true) {
                for (byte[] x : newTxHashes) {
                    System.out.print(toHexa(x) + " ");
                }
                System.out.println();
            }
            return buildTree(newTxHashes);
        }
    }

    public byte[] concatBytes(byte[] a, byte[] b) {
        byte[] bytes = new byte[a.length + b.length];
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        buffer.put(a);
        buffer.put(b);
        return buffer.array();
    }

    public static String toHexa(byte[] bytes) {
        StringBuilder s = new StringBuilder();
        for (byte b : bytes) {
            s.append(String.format("%02X", b));
        }
        return s.toString().toLowerCase();
    }
}
