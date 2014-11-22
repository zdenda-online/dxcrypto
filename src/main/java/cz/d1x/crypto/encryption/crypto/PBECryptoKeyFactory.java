package cz.d1x.crypto.encryption.crypto;

import cz.d1x.crypto.TextUtil;
import cz.d1x.crypto.encryption.EncryptionException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Base for key factories that provide password-based encryption keys.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public abstract class PBECryptoKeyFactory extends CryptoKeyFactory {

    private static final byte[] DEFAULT_SALT = TextUtil.getBytes("s4lTTTT-us3d~bY_re4l_m3n5", TextUtil.DEFAULT_ENCODING);
    private static final int DEFAULT_ITERATIONS = 27891;

    private final String algorithm;
    private final byte[] keyPassword;
    private final int keyLength;
    private final byte[] keySalt;
    private final int iterationsCount;

    protected PBECryptoKeyFactory(String algorithm, byte[] keyPassword, int keyLength) {
        this(algorithm, keyPassword, keyLength, DEFAULT_SALT, DEFAULT_ITERATIONS);
    }

    protected PBECryptoKeyFactory(String algorithm, byte[] keyPassword, int keyLength, byte[] keySalt) {
        this(algorithm, keyPassword, keyLength, keySalt, DEFAULT_ITERATIONS);
    }

    protected PBECryptoKeyFactory(String algorithm, byte[] keyPassword, int keyLength, byte[] keySalt, int iterationsCount) {
        this.algorithm = algorithm;
        this.keyPassword = keyPassword;
        this.keyLength = keyLength;
        this.keySalt = keySalt;
        this.iterationsCount = iterationsCount;
    }

    /**
     * Gets a name of algorithm for which PBE key should be provided.
     *
     * @return name of algorithm.
     */
    protected abstract String getAlgorithmName();

    @Override
    public Key getKey() throws EncryptionException {
        try {
            char[] keyEncoded = TextUtil.getString(keyPassword, TextUtil.DEFAULT_ENCODING).toCharArray();
            PBEKeySpec keySpec = new PBEKeySpec(keyEncoded, keySalt, iterationsCount, keyLength);
            SecretKey tmp = SecretKeyFactory.getInstance(getAlgorithmName()).generateSecret(keySpec);
            return new SecretKeySpec(tmp.getEncoded(), algorithm);
        } catch (InvalidKeySpecException e) {
            throw new EncryptionException("Encryption key specification is not valid", e);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException("Invalid key derivation algorithm", e);
        }
    }

}
