package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.Encoding;
import cz.d1x.dxcrypto.encryption.EncryptionAlgorithm;
import cz.d1x.dxcrypto.encryption.EncryptionException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

/**
 * Main implementation of encryption algorithms that use symmetric key based on existing javax.crypto package.
 * <p/>
 * This base implementation generates a new random initialization vector for every message and includes it in
 * encrypted message. This allows you to use one instance for different messages (otherwise it would be dangerous to use
 * same combination of key and IV for every message).
 * This base class also expects input to padded to the correct length, so it is not recommended to use NoPadding
 * variants of algorithm.
 * <p/>
 * Inputs and outputs from this encryption are bytes represented in HEX string.
 * <p/>
 * This class is immutable and can be considered thread safe. If you extend this class, it is recommended it
 * stays that way.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see AESBuilder
 * @see TripleDESBuilder
 */
public class SymmetricAlgorithm implements EncryptionAlgorithm {

    private final SecureRandom random = new SecureRandom();
    private final String encoding;
    private final Key key;
    private final Cipher cipher;

    /**
     * Creates a new instance of base algorithm.
     *
     * @param keyFactory factory used for creation of encryption key
     * @param encoding   encoding used for strings
     * @throws EncryptionException possible exception when algorithm cannot be created
     */
    public SymmetricAlgorithm(String cipherName, CryptoKeyFactory keyFactory, String encoding) throws EncryptionException {
        Encoding.checkEncoding(encoding);
        if (keyFactory == null) {
            throw new EncryptionException("Key factory must be set");
        }

        this.encoding = encoding;
        try {
            this.cipher = Cipher.getInstance(cipherName);
            this.key = keyFactory.getKey();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new EncryptionException("Invalid encryption algorithm", e);
        }
    }


    @Override
    public byte[] encrypt(byte[] input) throws EncryptionException {
        try {
            IvParameterSpec iv = generateIV();
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encryptedBytes = cipher.doFinal(input);
            return combineIvAndCipherText(iv.getIV(), encryptedBytes);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
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
        try {
            byte[][] ivAndCipherText = deriveIvAndCipherText(input);
            IvParameterSpec iv = new IvParameterSpec(ivAndCipherText[0]);
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            return cipher.doFinal(ivAndCipherText[1]);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new EncryptionException("Unable to decrypt message", e);
        }
    }

    @Override
    public String decrypt(String input) throws EncryptionException {
        byte[] textBytes = Encoding.fromHex(input);
        byte[] decryptedBytes = decrypt(textBytes);
        return Encoding.getString(decryptedBytes, encoding);
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
            throw new EncryptionException("Given input is too short, probably it was not encrypted by this library?");
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
}
