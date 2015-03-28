package cz.d1x.dxcrypto.encryption;

import cz.d1x.dxcrypto.common.Encoding;

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
public final class PBEKeyFactory implements KeyFactory<Key> {

    private final String encryptionAlgorithmName;
    private final String pbeKeyAlgorithmName;
    private final byte[] keyPassword;
    private final int keyLength;
    private final byte[] keySalt;
    private final int iterationsCount;

    protected PBEKeyFactory(String encryptionAlgorithmName, String pbeKeyAlgorithmName,
                            byte[] keyPassword, int keyLength, byte[] keySalt, int iterationsCount) {
        this.encryptionAlgorithmName = encryptionAlgorithmName;
        this.pbeKeyAlgorithmName = pbeKeyAlgorithmName;
        this.keyPassword = keyPassword;
        this.keyLength = keyLength;
        this.keySalt = keySalt;
        this.iterationsCount = iterationsCount;
    }

    @Override
    public Key getKey() throws EncryptionException {
        try {
            char[] keyEncoded = Encoding.getString(keyPassword).toCharArray();
            PBEKeySpec keySpec = new PBEKeySpec(keyEncoded, keySalt, iterationsCount, keyLength);
            SecretKey tmp = SecretKeyFactory.getInstance(pbeKeyAlgorithmName).generateSecret(keySpec);
            return new SecretKeySpec(tmp.getEncoded(), encryptionAlgorithmName);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new EncryptionException("Invalid key derivation algorithm", e);
        }
    }

}
