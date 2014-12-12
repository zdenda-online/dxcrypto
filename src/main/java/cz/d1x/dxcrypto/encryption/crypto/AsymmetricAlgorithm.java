package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.common.BytesRepresentation;
import cz.d1x.dxcrypto.common.Encoding;
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
 * <p>
 * Main implementation of encryption algorithms that use asymmetric key pair based on existing javax.crypto package.
 * </p><p>
 * This implementation can provide both encoding and decoding or only one of these functions depending on what key
 * was provided during instantiation. Public key is needed for encryption, private key for decryption.
 * </p><p>
 * Inputs and outputs from this encryption are bytes represented in HEX string.
 * </p><p>
 * This class is immutable and can be considered thread safe. It is not allowed to extend this class to ensure it stays
 * that way.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see RSABuilder
 */
public final class AsymmetricAlgorithm implements EncryptionAlgorithm {

    private final Cipher cipher;
    private final Key publicKey;
    private final Key privateKey;
    private final BytesRepresentation bytesRepresentation;
    private final String encoding;

    /**
     * Creates a new instance of base asymmetric algorithm.
     *
     * @param cipherName          name of crypto algorithm
     * @param publicKeyFactory    factory used for creation of public encryption key
     * @param privateKeyFactory   factory used for creation of privte encryption key
     * @param bytesRepresentation representation of byte arrays in String
     * @param encoding            encoding used for strings
     * @throws EncryptionException possible exception when algorithm cannot be created
     */
    protected AsymmetricAlgorithm(String cipherName, CryptoKeyFactory publicKeyFactory, CryptoKeyFactory privateKeyFactory,
                                  BytesRepresentation bytesRepresentation, String encoding) {
        Encoding.checkEncoding(encoding);
        if (publicKeyFactory == null && privateKeyFactory == null) {
            throw new EncryptionException("At least one (public/private) key factory must be set");
        }
        this.bytesRepresentation = bytesRepresentation;
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
            initCipher(true);
            return cipher.doFinal(input);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionException("Unable to encrypt message", e);
        }
    }

    @Override
    public String encrypt(String input) throws EncryptionException {
        byte[] textBytes = Encoding.getBytes(input, encoding);
        byte[] encryptedBytes = encrypt(textBytes);
        return bytesRepresentation.toString(encryptedBytes);
    }

    @Override
    public byte[] decrypt(byte[] input) throws EncryptionException {
        checkKey(false);
        try {
            initCipher(false);
            return cipher.doFinal(input);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionException("Unable to decrypt message", e);
        }
    }

    @Override
    public String decrypt(String input) throws EncryptionException {
        byte[] textBytes = bytesRepresentation.toBytes(input);
        byte[] decryptedBytes = decrypt(textBytes);
        return Encoding.getString(decryptedBytes, encoding);
    }

    private void initCipher(boolean isEncrypt) throws EncryptionException {
        try {
            cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, isEncrypt ? publicKey : privateKey);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("Unable to initialize cipher", e);
        }
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
