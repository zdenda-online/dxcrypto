package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.Encoding;
import cz.d1x.dxcrypto.encryption.EncryptionAlgorithm;
import cz.d1x.dxcrypto.encryption.EncryptionException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * Main implementation of encryption algorithms that use asymmetric key pair based on existing javax.crypto package.
 * <p/>
 * This implementation can provide both encoding and decoding or only one of these functions depending on what key
 * was provided during instantiation. Public key is needed for encryption, private key for decryption.
 * <p/>
 * Inputs and outputs from this encryption are bytes represented in HEX string.
 * <p/>
 * This class is immutable and can be considered thread safe. If you extend this class, it is recommended it
 * stays that way.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see RSABuilder
 */
public class AsymmetricAlgorithm implements EncryptionAlgorithm {

    private final String encoding;
    private final Key publicKey;
    private final Key privateKey;
    private final Cipher cipher;

    protected AsymmetricAlgorithm(String cipherName, CryptoKeyFactory publicKeyFactory, CryptoKeyFactory privateKeyFactory, String encoding) {
        Encoding.checkEncoding(encoding);
        if (publicKeyFactory == null && privateKeyFactory == null) {
            throw new EncryptionException("At least one (public/private) key factory must be set");
        }

        this.encoding = encoding;
        try {
            this.cipher = Cipher.getInstance(cipherName);
            this.publicKey = publicKeyFactory != null ? publicKeyFactory.getKey() : null;
            this.privateKey = privateKeyFactory != null ? privateKeyFactory.getKey() : null;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new EncryptionException("Invalid encryption algorithm", e);
        }
    }

    @Override
    public byte[] encrypt(byte[] input) throws EncryptionException {
        checkKey(true);
        try {
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(input);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            throw new EncryptionException("Unable to encrypt message", e);
        }
    }

    @Override
    public String encrypt(String input) throws EncryptionException {
        byte[] textBytes = Encoding.getBytes(input, encoding);
        byte[] encryptedBytes = encrypt(textBytes);
        return Encoding.toHex(encryptedBytes);
    }

    @Override
    public byte[] decrypt(byte[] input) throws EncryptionException {
        checkKey(false);
        try {
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(input);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            throw new EncryptionException("Unable to decrypt message", e);
        }
    }

    @Override
    public String decrypt(String input) throws EncryptionException {
        byte[] textBytes = Encoding.fromHex(input);
        byte[] decryptedBytes = decrypt(textBytes);
        return Encoding.getString(decryptedBytes, encoding);
    }

    private void checkKey(boolean isPublic) throws EncryptionException {
        if (isPublic && this.publicKey == null) {
            throw new EncryptionException("You didn't set public key during initialization, unable to encrypt messages");
        }
        if (!isPublic && this.privateKey == null) {
            throw new EncryptionException("You didn't set private key during initialization, unable to decrypt messages");
        }
    }
}
