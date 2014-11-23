package cz.d1x.dxcrypto.encryption.crypto;

/**
 * Builder for AES encryption algorithm with these properties:
 * <ul>
 * <li>Type of cipher: Symmetric</li>
 * <li>Operation mode: Cipher Block Chaining (CBC)</li>
 * <li>Input padding: PKCS#5</li>
 * <li>Encryption key: PBKDF2 with HMAC-SHA1 for key derivation (can be overridden)</li>
 * </ul>
 * <p/>
 * By default, PBKDF2 is used for key derivation. You can provide salt and iterations count for it.
 * If you want custom encryption key derivation, you can use {@link #AESBuilder(CryptoKeyFactory)}
 * constructor to specify custom factory for the key.
 * <p/>
 * Recommended usage:
 * <pre>
 * EncryptionAlgorithm aes = new AESBuilder("secret")
 *      .keySalt("saltForKeyDerivation") // optional
 *      .iterations(27) // optional
 *      .build();
 * </pre>
 * <p/>
 * Note that this builder is mutable but built instances are immutable and thus thread safe.
 * <p/>
 * For more information about the implementation, see {@link SymmetricAlgorithm}.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see SymmetricAlgorithm
 */
public class AESBuilder extends SymmetricAlgorithmBuilder {

    /**
     * Creates a new builder for AES encryption algorithm.
     *
     * @param keyPassword password for key derivation
     */
    public AESBuilder(byte[] keyPassword) {
        super(keyPassword);
    }

    /**
     * Creates a new builder for AES encryption algorithm.
     *
     * @param keyPassword password for key derivation
     */

    public AESBuilder(String keyPassword) {
        super(keyPassword);
    }

    /**
     * Crates a new builder for AES encryption algorithm.
     * Use this constructor if you want override default PBKDF2 for key derivation.
     *
     * @param customKeyFactory custom factory for encryption key
     */
    public AESBuilder(CryptoKeyFactory customKeyFactory) {
        super(customKeyFactory);
    }

    @Override
    protected String getAlgorithm() {
        return "AES/CBC/PKCS5Padding";
    }

    @Override
    protected String getShortAlgorithm() {
        return "AES";
    }

    @Override
    protected int getKeySize() {
        return 16 * 8;
    }
}
