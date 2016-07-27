package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.encryption.EncryptionException;
import cz.d1x.dxcrypto.encryption.EncryptionEngine;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class CryptoEngine implements EncryptionEngine {

    private final String cipherName;
    private final Key key;

    public CryptoEngine(String cipherName, Key key) {
        this.cipherName = cipherName;
        this.key = key;
        try {
            Cipher.getInstance(cipherName); // find out if i can create instances and retrieve block size
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new EncryptionException("Invalid encryption algorithm", e);
        }
    }

    @Override
    public byte[] encrypt(byte[] input, byte[] initVector) {
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
