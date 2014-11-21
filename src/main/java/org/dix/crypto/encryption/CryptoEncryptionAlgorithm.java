package org.dix.crypto.encryption;

import org.dix.crypto.encryption.impl.AES;
import org.dix.crypto.encryption.impl.TripleDES;
import org.dix.crypto.hash.HashingException;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

/**
 * Base class for implementations of {@link EncryptionAlgorithm} class which uses Java SDK's javax.crypto implementation.
 * <p/>
 * This base implementation generates a new random initialization vector for every message and includes it in
 * encrypted message. This allows you to use one instance for different messages (otherwise it would be dangerous to use
 * same combination of key and IV for every message).
 * <p/>
 * For key derivation, PBKDF2 algorithm is used along with HMAC-SHA1 as the pseudo-random function.
 * <p/>
 * This base class also expects input to padded to the correct length, so it is not recommended to use NoPadding
 * variants of algorithm.
 * <p/>
 * Inputs and outputs from this encryption are bytes represented in HEX string.
 * <p/>
 * This class is immutable and can be considered thread safe. If you extend this class, it is recommended it
 * stays that way.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see AES
 * @see TripleDES
 */
public abstract class CryptoEncryptionAlgorithm implements EncryptionAlgorithm {

    private final SecureRandom random = new SecureRandom();
    private final String encoding;
    private final Key key;
    private final Cipher cipher;

    /**
     * Creates a new instance of base algorithm.
     *
     * @param keyPassword password for encryption key derivation
     * @param keyLength   length of encryption key
     * @param encoding    encoding used for strings
     */
    protected CryptoEncryptionAlgorithm(byte[] keyPassword, int keyLength, String encoding) {
        if (!Charset.isSupported(encoding)) {
            throw new HashingException("Given encoding " + encoding + " is not supported");
        }
        if (keyPassword == null || keyPassword.length == 0) {
            throw new EncryptionException("Encryption keyPassword must be set");
        }

        this.encoding = encoding;
        try {
            this.cipher = Cipher.getInstance(getCipherName());
            this.key = deriveKey(keyPassword, keyLength);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new EncryptionException("Invalid encryption algorithm", e);
        }
    }

    /**
     * Gets a name of the cipher supported by crypto implementations.
     * It is recommended to use any variant with padding.
     *
     * @return name of cipher
     */
    protected abstract String getCipherName();


    @Override
    public byte[] encrypt(byte[] bytes) throws EncryptionException {
        try {
            IvParameterSpec iv = generateIV();
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encryptedBytes = cipher.doFinal(bytes);
            return combineIvAndCipherText(iv.getIV(), encryptedBytes);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new EncryptionException("Unable to encrypt message", e);
        }
    }

    @Override
    public String encrypt(String text) throws EncryptionException {
        try {
            byte[] textBytes = text.getBytes(encoding);
            byte[] encryptedBytes = encrypt(textBytes);
            return DatatypeConverter.printHexBinary(encryptedBytes).toLowerCase();
        } catch (UnsupportedEncodingException e) {
            throw new EncryptionException("Unsupported encoding", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] bytes) throws EncryptionException {
        try {
            byte[][] ivAndCipherText = deriveIvAndCipherText(bytes);
            IvParameterSpec iv = new IvParameterSpec(ivAndCipherText[0]);
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            return cipher.doFinal(ivAndCipherText[1]);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new EncryptionException("Unable to decrypt message", e);
        }
    }

    @Override
    public String decrypt(String text) throws EncryptionException {
        try {
            byte[] textBytes = DatatypeConverter.parseHexBinary(text.toLowerCase());
            byte[] decryptedBytes = decrypt(textBytes);
            return new String(decryptedBytes, encoding);
        } catch (UnsupportedEncodingException e) {
            throw new EncryptionException("Unsupported encoding", e);
        }
    }

    /**
     * Generates random initialization vector depending on cipher block size.
     *
     * @return random initialization vector
     */
    private IvParameterSpec generateIV() {
        byte[] iv = new byte[cipher.getBlockSize()];
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /**
     * Derives a key from given password and expected key length.
     *
     * @param keyPassword password for encryption key derivation
     * @param keyLength   length of encryption key
     * @return derived encryption key
     * @throws EncryptionException possible exception during key derivation
     */
    private Key deriveKey(byte[] keyPassword, int keyLength) throws EncryptionException {
        try {
            char[] keyEncoded = new String(keyPassword, encoding).toCharArray();
            // no need to introduce salt and iterations as constant - no-one is gonna find out here :-)
            byte[] salt = "s4lTTTT-us3d~bY_re4l_m3n5".getBytes(encoding);
            PBEKeySpec keySpec = new PBEKeySpec(keyEncoded, salt, 27891, keyLength);
            SecretKey tmp = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(keySpec);
            return new SecretKeySpec(tmp.getEncoded(), cutCipherName(getCipherName()));
        } catch (InvalidKeySpecException e) {
            throw new EncryptionException("Encryption keyPassword specification is not valid", e);
        } catch (UnsupportedEncodingException e) {
            throw new EncryptionException("Unsupported encoding", e);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException("Invalid key derivation algorithm", e);
        }
    }

    /**
     * Combines IV and cipher text together. IV is at the beginning and cipher text is the rest.
     *
     * @param iv         initialization vector
     * @param cipherText cipher text
     * @return combined IV and cipher text
     */
    private byte[] combineIvAndCipherText(byte[] iv, byte[] cipherText) {
        byte[] out = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(cipherText, 0, out, iv.length, cipherText.length);
        return out;
    }

    /**
     * Derives IV and cipher text from given input. It is expected that IV is at the beginning (its size is cipher block
     * size) and rest is cipher text.
     *
     * @param input input to be processed
     * @return arrays of IV (output[0]) and cipher text (output[1])
     */
    private byte[][] deriveIvAndCipherText(byte[] input) {
        if (input.length <= cipher.getBlockSize()) {
            throw new EncryptionException("Given input is too short, probably it was encrypted by someone else");
        }
        byte[][] out = new byte[2][];
        byte[] iv = new byte[cipher.getBlockSize()];
        byte[] cipherText = new byte[input.length - iv.length];
        System.arraycopy(input, 0, iv, 0, iv.length);
        System.arraycopy(input, iv.length, cipherText, 0, cipherText.length);
        out[0] = iv;
        out[1] = cipherText;
        return out;
    }

    private String cutCipherName(String cipherName) {
        int slashIdx = cipherName.indexOf("/");
        if (slashIdx != -1) {
            return cipherName.substring(0, slashIdx);
        } else {
            return cipherName;
        }
    }
}
