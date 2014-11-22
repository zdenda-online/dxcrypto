package cz.d1x.crypto.encryption.crypto;

import cz.d1x.crypto.TextUtil;
import cz.d1x.crypto.encryption.EncryptionException;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;

/**
 * RSA encryption algorithm with these properties:
 * <ul>
 * <li>Type of cipher: Asymmetric</li>
 * <li>Operation mode: Electronic Codebook (ECB)</li>
 * <li>Input padding: OAEP with SHA-256 (MGF1 for masks)</li>
 * </ul>
 * If you don't have key pair, you can generate some via {@link RSAKeysGenerator}.
 * <p/>
 * For more information about the implementation, see {@link CryptoAsymmetricKeyAlgorithm} from which this class extend.
 * <p/>
 * This class is immutable and can be considered thread safe.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see CryptoAsymmetricKeyAlgorithm
 * @see RSAKeysGenerator
 */
public class RSA extends CryptoAsymmetricKeyAlgorithm {

    /**
     * Creates a new RSA algorithm using given modulus and exponents.
     * This instance can be used for both encrypting and decrypting of messages.
     *
     * @param keys key pair (both public and private)
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public RSA(KeyPair keys) throws EncryptionException {
        super(publicKey(keys), privateKey(keys), TextUtil.DEFAULT_ENCODING);
    }

    /**
     * Creates a new RSA algorithm using given modulus and exponents.
     * This instance can be used for both encrypting and decrypting of messages.
     *
     * @param keys     key pair (both public and private)
     * @param encoding encoding for input and output strings
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public RSA(KeyPair keys, String encoding) throws EncryptionException {
        super(publicKey(keys), privateKey(keys), encoding);
    }

    /**
     * Creates a new RSA algorithm using given modulus and exponents.
     * This instance can be used only for one operation (encrypting or decrypting of messages).
     *
     * @param modulus  modulus of the key
     * @param exponent exponent of the key
     * @param isPublic flag whether given combination of modulus and exponent is for public or private key.
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public RSA(BigInteger modulus, BigInteger exponent, boolean isPublic) throws EncryptionException {
        super(isPublic ? publicKey(modulus, exponent) : null, isPublic ? null : privateKey(modulus, exponent), TextUtil.DEFAULT_ENCODING);
    }

    /**
     * Creates a new RSA algorithm using given modulus and exponents.
     * This instance can be used only for one operation (encrypting or decrypting of messages).
     *
     * @param modulus  modulus of the key
     * @param exponent exponent of the key
     * @param encoding encoding for input and output strings
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public RSA(BigInteger modulus, BigInteger exponent, boolean isPublic, String encoding) throws EncryptionException {
        super(isPublic ? publicKey(modulus, exponent) : null, isPublic ? null : privateKey(modulus, exponent), encoding);
    }

    /**
     * Creates a new RSA algorithm using given modulus and exponents.
     * This instance can be used for both encrypting and decrypting of messages.
     *
     * @param modulus         modulus for (d)encryption
     * @param publicExponent  public exponent for encryption
     * @param privateExponent private exponent for decryption
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public RSA(BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent) throws EncryptionException {
        super(publicKey(modulus, publicExponent), privateKey(modulus, privateExponent), TextUtil.DEFAULT_ENCODING);
    }

    /**
     * Creates a new RSA algorithm using given modulus and exponents.
     * This instance can be used for both encrypting and decrypting of messages.
     *
     * @param modulus         modulus for (d)encryption
     * @param publicExponent  public exponent for encryption
     * @param privateExponent private exponent for decryption
     * @param encoding        encoding for input and output strings
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public RSA(BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent, String encoding) throws EncryptionException {
        super(publicKey(modulus, publicExponent), privateKey(modulus, privateExponent), encoding);
    }

    @Override
    protected String getCipherName() {
        return "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    }

    private static CryptoKeyFactory publicKey(BigInteger modulus, BigInteger publicExponent) {
        if (modulus == null || publicExponent == null) {
            throw new EncryptionException("You must provide both modulus and exponent for public key");
        }
        return new RSAPublicKeyFactory(modulus, publicExponent);
    }

    private static CryptoKeyFactory privateKey(BigInteger modulus, BigInteger privateExponent) {
        if (modulus == null || privateExponent == null) {
            throw new EncryptionException("You must provide both modulus and exponent for public key");
        }
        return new RSAPrivateKeyFactory(modulus, privateExponent);
    }

    private static CryptoKeyFactory publicKey(KeyPair keys) {
        if (keys == null) {
            throw new EncryptionException("You must provide non-null key pair");
        }
        return key(keys.getPublic());
    }

    private static CryptoKeyFactory privateKey(KeyPair keys) {
        if (keys == null) {
            throw new EncryptionException("You must provide non-null key pair");
        }
        return key(keys.getPrivate());
    }

    private static CryptoKeyFactory key(final Key key) {
        return new CryptoKeyFactory() {
            @Override
            public Key getKey() throws EncryptionException {
                return key;
            }
        };
    }
}
