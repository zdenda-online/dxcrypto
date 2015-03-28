package cz.d1x.dxcrypto.encryption;

import cz.d1x.dxcrypto.common.BytesRepresentation;
import cz.d1x.dxcrypto.common.Encoding;
import cz.d1x.dxcrypto.common.HexRepresentation;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;

/**
 * Base builder for asymmetric key algorithms based on {@link AsymmetricCryptoAlgorithm}.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see AsymmetricCryptoAlgorithm
 */
public final class AsymmetricCryptoAlgorithmBuilder {

    private final String algorithmName;

    private KeyFactory<Key> publicKeyFactory;
    private KeyFactory<Key> privateKeyFactory;
    private BytesRepresentation bytesRepresentation = new HexRepresentation();
    private String encoding = Encoding.DEFAULT;

    protected AsymmetricCryptoAlgorithmBuilder(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    /**
     * Sets public key for encryption of messages.
     *
     * @param modulus  modulus of key
     * @param exponent exponent of public key
     * @return this instance
     */
    public AsymmetricCryptoAlgorithmBuilder publicKey(BigInteger modulus, BigInteger exponent) {
        if (modulus == null || exponent == null) {
            throw new EncryptionException("You must provide non-null both modulus and exponent for public key!");
        }
        this.publicKeyFactory = new RSAPublicKeyFactory(modulus, exponent);
        return this;
    }

    /**
     * Sets custom factory of public key for encryption of messages.
     *
     * @param publicKeyFactory factory of public key
     * @return this instance
     */
    public AsymmetricCryptoAlgorithmBuilder publicKey(KeyFactory<Key> publicKeyFactory) {
        if (publicKeyFactory == null) {
            throw new EncryptionException("You must provide non-null key factory!");
        }
        this.publicKeyFactory = publicKeyFactory;
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
    public AsymmetricCryptoAlgorithmBuilder privateKey(BigInteger modulus, BigInteger exponent) {
        if (modulus == null || exponent == null) {
            throw new IllegalArgumentException("You must provide non-null both modulus and exponent for private key");
        }
        this.privateKeyFactory = new RSAPrivateKeyFactory(modulus, exponent);
        return this;
    }

    /**
     * Sets custom factory of private key for decryption of messages.
     *
     * @param privateKeyFactory factory of private key
     * @return this instance
     * @throws IllegalArgumentException exception if passed factory is null
     */
    public AsymmetricCryptoAlgorithmBuilder privateKey(KeyFactory<Key> privateKeyFactory) {
        if (privateKeyFactory == null) {
            throw new IllegalArgumentException("You must provide non-null private key factory!");
        }
        this.privateKeyFactory = privateKeyFactory;
        return this;
    }

    /**
     * Sets both public and private key for both encryption and decryption.
     *
     * @param keyPair key pair
     * @return this instance
     * @throws IllegalArgumentException exception if passed key pair is null
     */
    public AsymmetricCryptoAlgorithmBuilder keyPair(final KeyPair keyPair) {
        if (keyPair == null) {
            throw new IllegalArgumentException("You must provide non-null key pair");
        }
        this.publicKeyFactory = new KeyFactory<Key>() {
            @Override
            public Key getKey() throws EncryptionException {
                return keyPair.getPublic();
            }
        };

        this.privateKeyFactory = new KeyFactory<Key>() {
            @Override
            public Key getKey() throws EncryptionException {
                return keyPair.getPrivate();
            }
        };
        return this;
    }

    /**
     * Sets how byte arrays will be represented in strings. By default {@link HexRepresentation} is used.
     *
     * @param bytesRepresentation byte array representation strategy
     * @return this instance
     * @throws IllegalArgumentException exception if passed BytesRepresentation is null
     */
    public AsymmetricCryptoAlgorithmBuilder bytesRepresentation(BytesRepresentation bytesRepresentation) {
        if (bytesRepresentation == null) {
            throw new IllegalArgumentException("You must provide non-null BytesRepresentation!");
        }
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
    public AsymmetricCryptoAlgorithmBuilder encoding(String encoding) {
        if (encoding == null) {
            throw new IllegalArgumentException("You must provide non-null encoding!");
        }
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
        if (publicKeyFactory == null && privateKeyFactory == null) {
            throw new IllegalArgumentException("At least one (public or private) key must be set");
        }
        return new AsymmetricCryptoAlgorithm(algorithmName, publicKeyFactory, privateKeyFactory, bytesRepresentation, encoding);
    }
}
