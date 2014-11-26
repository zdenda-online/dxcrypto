package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.Encoding;
import cz.d1x.dxcrypto.common.CombineAlgorithm;
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
 * output. This allows to use one instance for different messages (otherwise it would be dangerous to use
 * same combination of key and IV for every message). This combining of IV with the encrypted message implies that this
 * implementation will be compatible primarily with itself (this library). If another tool (on the other end) will
 * be used, you must pass information what {@link CombineAlgorithm} is used to that tool or implement new one which
 * will be compatible with it. Inputs and outputs of String-based methods expect/provide strings in HEX format.
 * <p/>
 * This base class also expects input to padded to the correct length, so it is not recommended to use NoPadding
 * variants of algorithm.
 * <p/>
 * Inputs and outputs from this encryption are bytes represented in HEX string.
 * <p/>
 * This class is immutable and can be considered thread safe. It is not allowed to extend this class to ensure it stays
 * that way.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see AESBuilder
 * @see TripleDESBuilder
 */
public final class SymmetricAlgorithm implements EncryptionAlgorithm {

    private final SecureRandom random = new SecureRandom();
    private final String cipherName;
    private final int blockSize; // CBC
    private final Key key;
    private final CombineAlgorithm combineAlgorithm;
    private final String encoding;

    /**
     * Creates a new instance of base algorithm.
     *
     * @param cipherName       name of crypto algorithm
     * @param keyFactory       factory used for creation of encryption key
     * @param combineAlgorithm algorithm for combining IV and cipher text
     * @param encoding         encoding used for strings
     * @throws EncryptionException possible exception when algorithm cannot be created
     */
    public SymmetricAlgorithm(String cipherName, CryptoKeyFactory keyFactory, CombineAlgorithm combineAlgorithm,
                              String encoding) throws EncryptionException {
        Encoding.checkEncoding(encoding);
        if (keyFactory == null) {
            throw new EncryptionException("Key factory must be set");
        }

        this.encoding = encoding;
        try {
            Cipher cipher = Cipher.getInstance(cipherName); // find out if i can create instances and retrieve block size
            this.cipherName = cipherName;
            this.blockSize = cipher.getBlockSize();
            this.key = keyFactory.getKey();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new EncryptionException("Invalid encryption algorithm", e);
        }
        this.combineAlgorithm = combineAlgorithm;
    }


    @Override
    public byte[] encrypt(byte[] input) throws EncryptionException {
        try {
            IvParameterSpec iv = generateIV();
            Cipher cipher = initCipher(iv, true);
            byte[] encryptedBytes = cipher.doFinal(input);
            return combineAlgorithm.combine(iv.getIV(), encryptedBytes);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionException("Unable to encrypt input", e);
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
            byte[][] ivAndCipherText = combineAlgorithm.split(input);
            IvParameterSpec iv = new IvParameterSpec(ivAndCipherText[0]);
            Cipher cipher = initCipher(iv, false);
            return cipher.doFinal(ivAndCipherText[1]);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionException("Unable to decrypt input", e);
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
        byte[] iv = new byte[blockSize];
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /**
     * Initializes cipher with given initialization vector.
     *
     * @param iv        initialization vector
     * @param isEncrypt flag whether cipher will be used for encryption (true) or decryption (false)
     * @return initialized cipher
     * @throws EncryptionException possible exception if cipher cannot be initialized
     */
    private Cipher initCipher(IvParameterSpec iv, boolean isEncrypt) throws EncryptionException {
        try {
            Cipher cipher = Cipher.getInstance(cipherName);
            cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key, iv);
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new EncryptionException("Unable to initialize cipher", e);
        }
    }
}
