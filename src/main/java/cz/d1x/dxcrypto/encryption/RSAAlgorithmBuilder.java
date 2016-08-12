package cz.d1x.dxcrypto.encryption;

import cz.d1x.dxcrypto.common.BytesRepresentation;
import cz.d1x.dxcrypto.common.Encoding;
import cz.d1x.dxcrypto.common.HexRepresentation;
import cz.d1x.dxcrypto.encryption.crypto.GenericRSAKeyFactory;

import java.math.BigInteger;

/**
 * Base builder for asymmetric key algorithms based on {@link GenericEncryptionAlgorithm}.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see GenericEncryptionAlgorithm
 */
public final class RSAAlgorithmBuilder {

    private BigInteger modulus;
    private BigInteger publicExponent;
    private BigInteger privateExponent;
    private AsymmetricEncryptionEngineFactory<RSAKey, RSAKey> engineFactory;
    private BytesRepresentation bytesRepresentation = new HexRepresentation();
    private String encoding = Encoding.DEFAULT;

    /**
     * Creates a new builder.
     *
     * @param engineFactory factory for encryption engine
     */
    public RSAAlgorithmBuilder(AsymmetricEncryptionEngineFactory<RSAKey, RSAKey> engineFactory) {
        this.engineFactory = engineFactory;
    }

    /**
     * Sets factory for encryption engine.
     *
     * @param engineFactory factory for encryption engine
     * @return this instance
     * @throws IllegalArgumentException exception if passed factory is null
     */
    public RSAAlgorithmBuilder engineFactory(AsymmetricEncryptionEngineFactory<RSAKey, RSAKey> engineFactory)
            throws IllegalArgumentException {
        if (engineFactory == null) throw new IllegalArgumentException("You must provide non-null engine factory!");
        this.engineFactory = engineFactory;
        return this;
    }

    /**
     * Sets public key for encryption of messages.
     *
     * @param modulus  modulus of key
     * @param exponent exponent of public key
     * @return this instance
     */
    public RSAAlgorithmBuilder publicKey(BigInteger modulus, BigInteger exponent) {
        if (modulus == null || exponent == null)
            throw new EncryptionException("You must provide non-null both modulus and exponent for public key!");
        this.modulus = modulus;
        this.publicExponent = exponent;
        return this;
    }

    /**
     * Sets private key for decryption of messages.
     *
     * @param modulus  modulus of key
     * @param exponent exponent of private key
     * @return this instance
     * @throws IllegalArgumentException exception if passed modulus or exponent is null
     */
    public RSAAlgorithmBuilder privateKey(BigInteger modulus, BigInteger exponent) {
        if (modulus == null || exponent == null)
            throw new IllegalArgumentException("You must provide non-null both modulus and exponent for private key");
        this.modulus = modulus;
        this.privateExponent = exponent;
        return this;
    }

    /**
     * Sets how byte arrays will be represented in strings. By default {@link HexRepresentation} is used.
     *
     * @param bytesRepresentation byte array representation strategy
     * @return this instance
     * @throws IllegalArgumentException exception if passed BytesRepresentation is null
     */
    public RSAAlgorithmBuilder bytesRepresentation(BytesRepresentation bytesRepresentation) {
        if (bytesRepresentation == null)
            throw new IllegalArgumentException("You must provide non-null BytesRepresentation!");
        this.bytesRepresentation = bytesRepresentation;
        return this;
    }

    /**
     * Sets encoding for strings in input and output.
     *
     * @param encoding encoding to be set
     * @return this instance
     * @throws IllegalArgumentException exception if given encoding is null or not supported
     */
    public RSAAlgorithmBuilder encoding(String encoding) {
        if (encoding == null) throw new IllegalArgumentException("You must provide non-null encoding!");
        Encoding.checkEncoding(encoding);
        this.encoding = encoding;
        return this;
    }

    /**
     * Builds a new instance of encryption algorithm.
     *
     * @return algorithm instance
     * @throws EncryptionException possible exception when encryption algorithm cannot be built
     */
    public EncryptionAlgorithm build() throws IllegalArgumentException {
        EncryptionKeyFactory<RSAKey> publicKeyFactory = (publicExponent != null) ? new GenericRSAKeyFactory(modulus, publicExponent, true) : null;
        EncryptionKeyFactory<RSAKey> privateKeyFactory = (privateExponent != null) ? new GenericRSAKeyFactory(modulus, privateExponent, false) : null;
        EncryptionEngine engine = engineFactory.newEngine(publicKeyFactory, privateKeyFactory);
        return new GenericEncryptionAlgorithm(engine, bytesRepresentation, encoding);
    }
}
