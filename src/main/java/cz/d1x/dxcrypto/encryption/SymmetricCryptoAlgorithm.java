package cz.d1x.dxcrypto.encryption;

import cz.d1x.dxcrypto.common.ByteArrayFactory;
import cz.d1x.dxcrypto.common.BytesRepresentation;
import cz.d1x.dxcrypto.common.CombiningSplitting;
import cz.d1x.dxcrypto.common.Encoding;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

/**
 * <p>
 * Main implementation of encryption algorithms that use symmetric key based on existing javax.crypto package.
 * </p><p>
 * This base implementation generates a new random initialization vector for every message and includes it in
 * output. This allows to use one instance for different messages (otherwise it would be dangerous to use
 * same combination of key and IV for every message). This combining of IV with the encrypted message implies that this
 * implementation will be compatible primarily with itself (this library). If another tool (on the other end) will
 * be used, you must pass information what {@link CombiningSplitting} is used to that tool or implement new one which
 * will be compatible with it. Inputs and outputs of String-based methods expect/provide strings in HEX format.
 * </p><p>
 * This base class also expects input to padded to the correct length, so it is <strong>not</strong> recommended to use
 * NoPadding variants of algorithm.
 * </p><p>
 * This class is immutable and can be considered thread safe. It is not allowed to extend this class to ensure it stays
 * that way.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public final class SymmetricCryptoAlgorithm implements EncryptionAlgorithm {

    private final String cipherName;
    private final int blockSize; // CBC
    private final Key key;
    private final ByteArrayFactory ivFactory;
    private final CombiningSplitting ivOutputCombining;
    private final BytesRepresentation bytesRepresentation;
    private final String encoding;

    /**
     * Creates a new instance of base symmetric algorithm.
     *
     * @param cipherName          name of crypto algorithm
     * @param keyFactory          factory used for creation of encryption key
     * @param ivFactory           factory used for creation of initialization vector
     * @param ivOutputCombining   algorithm for combining/splitting IV and cipher text
     * @param bytesRepresentation representation of byte arrays in String
     * @param encoding            encoding used for strings
     * @throws EncryptionException possible exception when algorithm cannot be created
     */
    protected SymmetricCryptoAlgorithm(String cipherName,
                                       KeyFactory<Key> keyFactory,
                                       ByteArrayFactory ivFactory,
                                       CombiningSplitting ivOutputCombining,
                                       BytesRepresentation bytesRepresentation,
                                       String encoding) throws EncryptionException {
        this.ivFactory = ivFactory;
        this.ivOutputCombining = ivOutputCombining;
        this.bytesRepresentation = bytesRepresentation;
        this.encoding = encoding;
        try {
            Cipher cipher = Cipher.getInstance(cipherName); // find out if i can create instances and retrieve block size
            this.blockSize = cipher.getBlockSize();
            this.cipherName = cipherName;
            this.key = keyFactory.getKey();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new EncryptionException("Invalid encryption algorithm", e);
        }
    }


    @Override
    public byte[] encrypt(byte[] input) throws EncryptionException {
        if (input == null) {
            throw new IllegalArgumentException("Input data for encryption cannot be null!");
        }
        try {
            IvParameterSpec iv = getIv();
            Cipher cipher = createCipher(iv, true);
            byte[] encryptedBytes = cipher.doFinal(input);
            return ivOutputCombining.combine(iv.getIV(), encryptedBytes);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionException("Unable to encrypt input", e);
        }
    }

    @Override
    public String encrypt(String input) throws EncryptionException {
        if (input == null) {
            throw new IllegalArgumentException("Input data for encryption cannot be null!");
        }
        byte[] textBytes = Encoding.getBytes(input, encoding);
        byte[] encryptedBytes = encrypt(textBytes);
        return bytesRepresentation.toString(encryptedBytes);
    }

    @Override
    public byte[] decrypt(byte[] input) throws EncryptionException {
        if (input == null) {
            throw new IllegalArgumentException("Input data for decryption cannot be null!");
        }
        try {
            byte[][] ivAndCipherText = ivOutputCombining.split(input);
            if (ivAndCipherText == null || ivAndCipherText.length != 2) {
                throw new EncryptionException("Splitting of input into two parts during decryption produced wrong " +
                        "number of parts. Is the input or used implementation of CombiningSplitting correct?");
            }
            IvParameterSpec iv = new IvParameterSpec(ivAndCipherText[0]);
            Cipher cipher = createCipher(iv, false);
            return cipher.doFinal(ivAndCipherText[1]);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionException("Unable to decrypt input", e);
        }
    }

    @Override
    public String decrypt(String input) throws EncryptionException {
        if (input == null) {
            throw new IllegalArgumentException("Input data for decryption cannot be null!");
        }
        byte[] textBytes = bytesRepresentation.toBytes(input);
        byte[] decryptedBytes = decrypt(textBytes);
        return Encoding.getString(decryptedBytes, encoding);
    }

    private IvParameterSpec getIv() {
        byte[] ivBytes = ivFactory.getBytes(blockSize);
        if (ivBytes.length != blockSize) {
            throw new IllegalArgumentException("Generated initialization vector has size " + ivBytes.length +
                    " bytes but must be size equal to block size " + blockSize + " bytes");
        }
        return new IvParameterSpec(ivBytes);
    }

    /**
     * Creates and initializes cipher with given initialization vector.
     * It creates a new {@link Cipher} instance for every operation to ensure immutability (thread safety) of algorithm.
     */
    private Cipher createCipher(IvParameterSpec iv, boolean isEncrypt) throws EncryptionException {
        try {
            Cipher cipher = Cipher.getInstance(cipherName);
            cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key, iv);
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new EncryptionException("Unable to initialize cipher", e);
        }
    }
}
