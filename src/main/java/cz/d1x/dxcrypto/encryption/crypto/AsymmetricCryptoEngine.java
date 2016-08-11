package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.encryption.EncryptionEngine;
import cz.d1x.dxcrypto.encryption.EncryptionException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * Implementation of encryption engine that uses javax.crypto implementations for asymmetric encryption.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class AsymmetricCryptoEngine implements EncryptionEngine {

    private final String cipherName;
    private final Key encryptionKey;
    private final Key decryptionKey;


    public AsymmetricCryptoEngine(String cipherName, Key encryptionKey, Key decryptionKey) {
        this.cipherName = cipherName;
        this.encryptionKey = encryptionKey;
        this.decryptionKey = decryptionKey;
        try {
            Cipher.getInstance(cipherName); // find out if i can create instances and retrieve block size
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new EncryptionException("Invalid encryption algorithm", e);
        }
    }

    @Override
    public byte[] encrypt(byte[] input, byte[] initVector) throws EncryptionException {
        if (encryptionKey == null) {
            throw new EncryptionException("You didn't set public key during initialization, unable to encrypt messages");
        }
        return doOperation(input, true);
    }

    @Override
    public byte[] decrypt(byte[] input, byte[] initVector) throws EncryptionException {
        if (decryptionKey == null) {
            throw new EncryptionException("You didn't set private key during initialization, unable to decrypt messages");
        }
        return doOperation(input, false);
    }

    private byte[] doOperation(byte[] input, boolean isEncrypt) {
        try {
            Cipher cipher = Cipher.getInstance(cipherName);
            cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, isEncrypt ? encryptionKey : decryptionKey);
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException
                | IllegalBlockSizeException e) {
            throw new EncryptionException("Unable to initialize cipher", e);
        }
    }
}
