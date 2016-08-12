package cz.d1x.dxcrypto.encryption.key;

/**
 * Created by d1x on 8/12/16.
 */
public class DerivedKeyParameters {

    private final byte[] password;
    private final byte[] salt;
    private final int iterations;
    private final int keySize;

    public DerivedKeyParameters(byte[] password, byte[] salt, int iterations, int keySize) {
        this.password = password;
        this.salt = salt;
        this.iterations = iterations;
        this.keySize = keySize;
    }

    public byte[] getPassword() {
        return password;
    }

    public byte[] getSalt() {
        return salt;
    }

    public int getIterations() {
        return iterations;
    }

    public int getKeySize() {
        return keySize;
    }
}
