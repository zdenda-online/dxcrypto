package cz.d1x.dxcrypto.encryption.crypto;

/**
 * Builder for RSA encryption algorithm with these properties:
 * <ul>
 * <li>Type of cipher: Asymmetric</li>
 * <li>Operation mode: Electronic Codebook (ECB)</li>
 * <li>Input padding: OAEP with SHA-256 (MGF1 for masks)</li>
 * </ul>
 * If you don't have key pair, you can generate some via {@link RSAKeysGenerator}.
 * Recommended usage:
 * <pre>
 *     BigInteger modulus =
 *     EncryptionAlgorithm aes = new RSABuilder()
 *                                    .publicKey("myKeySalt) // optional
 *                                    .iterations(27) // optional
 *                                    .build();
 * </pre>
 * <p>
 * Note that this builder is mutable but built instances are immutable and thus thread safe.
 * For more information about the implementation, see {@link SymmetricAlgorithm}.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see AsymmetricAlgorithm
 * @see RSAKeysGenerator
 */
public class RSABuilder extends AsymmetricAlgorithmBuilder {

    /**
     * Creates a new builder for RSA encryption algorithm.
     */
    public RSABuilder() {
    }

    @Override
    protected String getAlgorithm() {
        return "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    }
}
