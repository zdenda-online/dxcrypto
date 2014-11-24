package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.Encoding;
import cz.d1x.dxcrypto.encryption.EncryptionAlgorithm;
import cz.d1x.dxcrypto.encryption.EncryptionAlgorithmBuilder;
import cz.d1x.dxcrypto.encryption.EncryptionException;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;

/**
 * Base builder for asymmetric key algorithms.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see AsymmetricAlgorithm
 */
public abstract class AsymmetricAlgorithmBuilder implements EncryptionAlgorithmBuilder {

    private CryptoKeyFactory publicKeyFactory;
    private CryptoKeyFactory privateKeyFactory;
    private String encoding;

    /**
     * Gets a name of algorithm supported by crypto.
     *
     * @return algorithm name
     */
    protected abstract String getAlgorithm();

    protected AsymmetricAlgorithmBuilder() {
    }

    /**
     * Sets public key for encryption of messages.
     *
     * @param modulus  modulus of key
     * @param exponent exponent of public key
     * @return this instance
     */
    public AsymmetricAlgorithmBuilder publicKey(BigInteger modulus, BigInteger exponent) {
        if (modulus == null || exponent == null) {
            throw new EncryptionException("You must provide both modulus and exponent for public key");
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
    public AsymmetricAlgorithmBuilder publicKey(CryptoKeyFactory publicKeyFactory) {
        this.publicKeyFactory = publicKeyFactory;
        return this;
    }

    /**
     * Sets private key for decryption of messages.
     *
     * @param modulus  modulus of key
     * @param exponent exponent of private key
     * @return this instance
     */
    public AsymmetricAlgorithmBuilder privateKey(BigInteger modulus, BigInteger exponent) {
        if (modulus == null || exponent == null) {
            throw new EncryptionException("You must provide both modulus and exponent for private key");
        }
        this.privateKeyFactory = new RSAPrivateKeyFactory(modulus, exponent);
        return this;
    }

    /**
     * Sets custom factory of private key for decryption of messages.
     *
     * @param privateKeyFactory factory of private key
     * @return this instance
     */
    public AsymmetricAlgorithmBuilder privateKey(CryptoKeyFactory privateKeyFactory) {
        this.privateKeyFactory = privateKeyFactory;
        return this;
    }

    /**
     * Sets both public and private key for both encryption and decryption.
     *
     * @param keyPair key pair
     * @return this instance
     */
    public AsymmetricAlgorithmBuilder keyPair(final KeyPair keyPair) {
        if (keyPair == null) {
            throw new EncryptionException("You must provide non-null key pair");
        }
        this.publicKeyFactory = new CryptoKeyFactory() {
            @Override
            public Key getKey() throws EncryptionException {
                return keyPair.getPublic();
            }
        };

        this.privateKeyFactory = new CryptoKeyFactory() {
            @Override
            public Key getKey() throws EncryptionException {
                return keyPair.getPrivate();
            }
        };
        return this;
    }

    /**
     * Sets encoding for strings in input and output.
     *
     * @param encoding encoding to be set
     * @return this instance
     */
    public AsymmetricAlgorithmBuilder encoding(String encoding) {
        this.encoding = encoding;
        return this;
    }

    @Override
    public EncryptionAlgorithm build() throws EncryptionException {
        if (encoding == null) {
            encoding = Encoding.UTF_8;
        }
        return new AsymmetricAlgorithm(getAlgorithm(), publicKeyFactory, privateKeyFactory, encoding);
    }
}
