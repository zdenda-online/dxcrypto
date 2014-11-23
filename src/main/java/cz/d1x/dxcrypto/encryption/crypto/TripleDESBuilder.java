package cz.d1x.dxcrypto.encryption.crypto;

/**
 * Builder for Triple DES (or 3DES) encryption algorithm with these properties:
 * <ul>
 * <li>Type of cipher: Symmetric</li>
 * <li>Operation mode: Cipher Block Chaining (CBC)</li>
 * <li>Input padding: PKCS#5</li>
 * <li>Encryption key: PBKDF2 with HMAC-SHA1 for key derivation (can be overridden)</li>
 * </ul>
 * <p/>
 * By default, PBKDF2 is used for key derivation. You can provide salt and iterations count for it.
 * If you want custom encryption key derivation, you can use {@link #TripleDESBuilder(CryptoKeyFactory)}
 * constructor to specify custom factory for the key.
 * <p/>
 * Recommended usage:
 * <pre>
 * EncryptionAlgorithm des = new TripleDESBuilder("secret")
 *      .keySalt("saltForKeyDerivation") // optional
 *      .iterations(27) // optional
 *      .build();
 * </pre>
 * <p/>
 * For more information about the implementation, see {@link SymmetricAlgorithm}.
 * <p/>
 * Note that this builder is mutable but built instances are immutable and thus thread safe.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see SymmetricAlgorithm
 */
public class TripleDESBuilder extends SymmetricAlgorithmBuilder {

    /**
     * Creates a new builder for 3DES encryption algorithm.
     *
     * @param keyPassword password for key derivation
     */
    public TripleDESBuilder(byte[] keyPassword) {
        super(keyPassword);
    }

    /**
     * Creates a new builder for 3DES encryption algorithm.
     *
     * @param keyPassword password for key derivation
     */

    public TripleDESBuilder(String keyPassword) {
        super(keyPassword);
    }

    /**
     * Crates a new builder for 3DES encryption algorithm.
     * Use this constructor if you want override default PBKDF2 for key derivation.
     *
     * @param customKeyFactory custom factory for encryption key
     */
    public TripleDESBuilder(CryptoKeyFactory customKeyFactory) {
        super(customKeyFactory);
    }

    @Override
    protected String getAlgorithm() {
        return "DESede/CBC/PKCS5Padding";
    }

    @Override
    protected String getShortAlgorithm() {
        return "DESede";
    }

    @Override
    protected int getKeySize() {
        return 24 * 8;
    }
}
