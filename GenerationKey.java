import java.security.*;

public class GenerationKey {
    private KeyPairGenerator keyGen;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public GenerationKey(int keyLength) throws NoSuchAlgorithmException {
        this.keyGen = KeyPairGenerator.getInstance("RSA");
        this.keyGen.initialize(keyLength);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public KeyPairGenerator getKeyGen() {
        return keyGen;
    }

    public void setKeyGen(KeyPairGenerator keyGen) {
        this.keyGen = keyGen;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }
}
