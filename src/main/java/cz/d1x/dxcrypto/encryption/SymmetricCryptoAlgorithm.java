package cz.d1x.dxcrypto.encryption;

import cz.d1x.dxcrypto.common.BytesRepresentation;
import cz.d1x.dxcrypto.common.CombineSplitAlgorithm;
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
 * be used, you must pass information what {@link CombineSplitAlgorithm} is used to that tool or implement new one which
 * will be compatible with it. Inputs and outputs of String-based methods expect/provide strings in HEX format.
 * </p><p>
 * This base class also expects input to padded to the correct length, so it is <strong>not</strong> recommended to use
 * NoPadding variants of algorithm.
 * </p><p>
 * Inputs and outputs from this encryption are bytes represented in HEX string.
 * </p><p>
 * This class is immutable and can be considered thread safe. It is not allowed to extend this class to ensure it stays
 * that way.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public final class SymmetricCryptoAlgorithm implements EncryptionAlgorithm {

    private final SecureRandom random = new SecureRandom();
    private final Cipher cipher;
    private final int blockSize; // CBC
    private final Key key;
    private final CombineSplitAlgorithm combineSplitAlgorithm;
    private final BytesRepresentation bytesRepresentation;
    private final String encoding;

    /**
     * Creates a new instance of base symmetric algorithm.
     *
     * @param cipherName            name of crypto algorithm
     * @param keyFactory            factory used for creation of encryption key
     * @param combineSplitAlgorithm algorithm for combining/splitting IV and cipher text
     * @param bytesRepresentation   representation of byte arrays in String
     * @param encoding              encoding used for strings
     * @throws EncryptionException possible exception when algorithm cannot be created
     */
    protected SymmetricCryptoAlgorithm(String cipherName, KeyFactory<Key> keyFactory, CombineSplitAlgorithm combineSplitAlgorithm,
                                       BytesRepresentation bytesRepresentation, String encoding) throws EncryptionException {
        this.combineSplitAlgorithm = combineSplitAlgorithm;
        this.bytesRepresentation = bytesRepresentation;
        this.encoding = encoding;
        try {
            cipher = Cipher.getInstance(cipherName); // find out if i can create instances and retrieve block size
            this.blockSize = cipher.getBlockSize();
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
            IvParameterSpec iv = generateIV();
            initCipher(iv, true);
            byte[] encryptedBytes = cipher.doFinal(input);
            return combineSplitAlgorithm.combine(iv.getIV(), encryptedBytes);
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
            byte[][] ivAndCipherText = combineSplitAlgorithm.split(input);
            if (ivAndCipherText == null || ivAndCipherText.length != 2) {
                throw new EncryptionException("Splitting of input into two parts during decryption produced wrong " +
                        "number of parts. Is the input or used implementation of CombineSplitAlgorithm correct?");
            }
            IvParameterSpec iv = new IvParameterSpec(ivAndCipherText[0]);
            initCipher(iv, false);
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

    /**
     * Generates random initialization vector depending on cipher block size.
     *
     * @return random initialization vector
     */
    private IvParameterSpec generateIV() {
        byte[] iv = new byte[blockSize];
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /**
     * Initializes cipher with given initialization vector.
     *
     * @param iv        initialization vector
     * @param isEncrypt flag whether cipher will be used for encryption (true) or decryption (false)
     * @throws EncryptionException possible exception if cipher cannot be initialized
     */
    private void initCipher(IvParameterSpec iv, boolean isEncrypt) throws EncryptionException {
        try {
            cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key, iv);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new EncryptionException("Unable to initialize cipher", e);
        }
    }
}
