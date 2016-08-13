package cz.d1x.dxcrypto.encryption.key;

/**
 * Parameters for derivation of encryption key by any hash function.
 */
public class DerivedKeyParams {

    private final byte[] password;
    private final byte[] salt;
    private final int iterations;
    private final int keySize;

    public DerivedKeyParams(byte[] password, byte[] salt, int iterations, int keySize) {
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
