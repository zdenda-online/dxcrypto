package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.encryption.EncryptionEngine;
import cz.d1x.dxcrypto.encryption.EncryptionException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * Implementation of encryption engine that uses javax.crypto implementations for symmetric encryption.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class SymmetricCryptoEngine implements EncryptionEngine {

    private final String cipherName;
    private final Key key;

    public SymmetricCryptoEngine(String cipherName, byte[] key) throws EncryptionException {
        this.cipherName = cipherName;
        String shortCipherName = cipherName.contains("/") ? cipherName.substring(0, cipherName.indexOf("/")) : cipherName;
        this.key = new SecretKeySpec(key, shortCipherName);
        try {
            Cipher.getInstance(cipherName); // find out if i can create instances and retrieve block size
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new EncryptionException("Invalid encryption algorithm", e);
        }
    }

    @Override
    public byte[] encrypt(byte[] input, byte[] initVector) throws EncryptionException {
        return doOperation(input, initVector, true);
    }

    @Override
    public byte[] decrypt(byte[] input, byte[] initVector) {
        return doOperation(input, initVector, false);
    }

    private byte[] doOperation(byte[] input, byte[] initVector, boolean isEncrypt) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector);
            Cipher cipher = Cipher.getInstance(cipherName);
            cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key, iv);
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new EncryptionException("Unable to encrypt input", e);
        }
    }
}
