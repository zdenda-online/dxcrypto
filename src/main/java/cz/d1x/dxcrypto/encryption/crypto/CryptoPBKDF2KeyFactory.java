package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.common.ByteArray;
import cz.d1x.dxcrypto.common.Encoding;
import cz.d1x.dxcrypto.encryption.key.DerivedKeyParameters;
import cz.d1x.dxcrypto.encryption.EncryptionException;
import cz.d1x.dxcrypto.encryption.key.EncryptionKeyFactory;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Key factory that uses implementation of PBKDF2 function from javax.crypto for key derivation.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class CryptoPBKDF2KeyFactory implements EncryptionKeyFactory<ByteArray, DerivedKeyParameters> {

    @Override
    public ByteArray newKey(DerivedKeyParameters keyParams) {
        // A bug in PBEKeySpec as it accepts first parameter only char[] and does not allow custom byte[]
        // This can cause incompatibility with other engines when used different than String-based key password
        // https://bugs.openjdk.java.net/browse/JDK-4703384
        char[] keyEncoded = Encoding.getString(keyParams.getPassword()).toCharArray(); // likely we cannot do any better

        PBEKeySpec keySpec = new PBEKeySpec(keyEncoded, keyParams.getSalt(), keyParams.getIterations(), keyParams.getKeySize());
        try {
            SecretKey key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(keySpec);
            return new ByteArray(key.getEncoded());
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new EncryptionException("Key cannot be created", e);
        }
    }
}
