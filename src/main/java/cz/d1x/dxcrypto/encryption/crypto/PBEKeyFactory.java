package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.Encoding;
import cz.d1x.dxcrypto.encryption.EncryptionException;

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
public abstract class PBEKeyFactory extends CryptoKeyFactory {

    private final String algorithm;
    private final byte[] keyPassword;
    private final int keyLength;
    private final byte[] keySalt;
    private final int iterationsCount;

    protected PBEKeyFactory(String algorithm, byte[] keyPassword, int keyLength, byte[] keySalt, int iterationsCount) {
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
            char[] keyEncoded = Encoding.getString(keyPassword).toCharArray();
            PBEKeySpec keySpec = new PBEKeySpec(keyEncoded, keySalt, iterationsCount, keyLength);
            SecretKey tmp = SecretKeyFactory.getInstance(getAlgorithmName()).generateSecret(keySpec);
            return new SecretKeySpec(tmp.getEncoded(), algorithm);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new EncryptionException("Invalid key derivation algorithm", e);
        }
    }

}
