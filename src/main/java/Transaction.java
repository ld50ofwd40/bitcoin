import java.security.PublicKey;

public class Transaction {
    private byte[] txId;
    private PublicKey ownerPK;
    private byte[] prevTxId;
    private byte[] digitalSignature;

    public void setTxId(byte[] txId) {
        this.txId = txId;
    }

    public void setOwnerPK(PublicKey ownerPK) {
        this.ownerPK = ownerPK;
    }

    public void setPrevTxId(byte[] prevTxId) {
        this.prevTxId = prevTxId;
    }

    public void setDigitalSignature(byte[] digitalSignature) {
        this.digitalSignature = digitalSignature;
    }

    public byte[] getTxId() {
        return txId;
    }

    public PublicKey getOwnerPK() {
        return ownerPK;
    }

    public byte[] getPrevTxId() {
        return prevTxId;
    }

    public byte[] getDigitalSignature() {
        return digitalSignature;
    }

}
