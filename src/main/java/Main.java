import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class Main {
    public static void main(String[] args) {

        List<Peer> peers = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            Peer peer = new Peer();
            peers.add(peer);
        }

        Random random = new Random();

        Node node = new Node(0);
        for (int i = 0; i < 3; i++) {
            Peer sender;
            Peer receiver = peers.get(random.nextInt(peers.size()));
            byte[] signature = receiver.signTransaction(receiver.keyPair.getPublic(), new byte[32]);
            node.addTransaction(receiver.keyPair.getPublic(), signature, new byte[32]);
            do {
                sender = receiver;
                receiver = peers.get(random.nextInt(peers.size()));
                byte[] prevTxHash = node.getLastTransaction().getTxId();
                signature = sender.signTransaction(receiver.keyPair.getPublic(), prevTxHash);
                node.addTransaction(receiver.keyPair.getPublic(), signature, prevTxHash);
            } while (!node.mineBlock(node.blockchain.get(node.blockchain.size() - 1)));
            System.out.print("Block transactions are verified: ");
            System.out.println(node.verifyBlockTransactions(node.blockchain.size() - 1));
            System.out.println("==================================================================================\n");
            node.createBlock(node.getLastBlock().prevBlockHash);
        }

    }

    /*
    public static String toHexa(byte[] bytes) {
        StringBuilder s = new StringBuilder();
        for (byte b : bytes) {
            s.append(String.format("%02X", b));
        }
        return s.toString().toLowerCase();
    }

    public static byte[] toBytes(String str) {
        byte[] bytes = new byte[str.length() / 2];
        for (int i = 0; i < str.length() / 2; i++) {
            Integer val = Integer.parseInt(str.substring(2 * i, 2 * (i + 1)), 16);
            bytes[i] = (byte) val.intValue();
        }
        return bytes;
    }
    */
}