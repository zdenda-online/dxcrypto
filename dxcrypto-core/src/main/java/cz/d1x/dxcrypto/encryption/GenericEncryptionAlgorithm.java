package cz.d1x.dxcrypto.encryption;

import cz.d1x.dxcrypto.common.ByteArrayFactory;
import cz.d1x.dxcrypto.common.BytesRepresentation;
import cz.d1x.dxcrypto.common.CombiningSplitting;
import cz.d1x.dxcrypto.common.Encoding;

/**
 * <p>
 * Main implementation for encryption algorithms that have all logic based on passed {@link EncryptionEngine}.
 * </p><p>
 * The logic is based on whether it is intended for use with or without initialization vector.
 * <ul>
 * <li>Without IV: It simply calls underlying {@link EncryptionEngine} and optionally does encoding/decoding
 * operations.</li>
 * <li>With IV: It generates a new initialization vector from given {@link ByteArrayFactory} and includes in every
 * message based on used {@link CombiningSplitting}. This allows to use one instance for different messages (otherwise
 * it would not be safe to use same combination of key and IV for every message).</li>
 * </ul>
 * <p>
 * This class is immutable and can be considered thread safe. It is not allowed to extend this class to ensure it stays
 * that way.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public final class GenericEncryptionAlgorithm implements EncryptionAlgorithm {

    private final boolean usesInitVector;
    private final EncryptionEngine engine;
    private final int blockSize;
    private final ByteArrayFactory ivFactory;
    private final CombiningSplitting ivOutputCombining;
    private final BytesRepresentation bytesRepresentation;
    private final String encoding;

    /**
     * Creates a new instance of generic algorithm that uses initialization vector.
     *
     * @param engine              engine for encryption
     * @param bytesRepresentation representation of byte arrays in String
     * @param encoding            encoding used for strings
     * @param blockSize           size of block
     * @param ivFactory           factory used for creation of initialization vector
     * @param ivOutputCombining   algorithm for combining/splitting IV and cipher text
     * @throws EncryptionException exception when algorithm cannot be created
     */
    GenericEncryptionAlgorithm(EncryptionEngine engine,
                               BytesRepresentation bytesRepresentation,
                               String encoding,
                               int blockSize,
                               ByteArrayFactory ivFactory,
                               CombiningSplitting ivOutputCombining) throws EncryptionException {
        this.engine = engine;
        this.bytesRepresentation = bytesRepresentation;
        this.encoding = encoding;

        this.usesInitVector = true;
        this.blockSize = blockSize;
        this.ivFactory = ivFactory;
        this.ivOutputCombining = ivOutputCombining;
    }

    /**
     * Creates a new instance of generic algorithm that does NOT use initialization vector.
     *
     * @param engine              engine for encryption
     * @param bytesRepresentation representation of byte arrays in String
     * @param encoding            encoding used for strings
     * @throws EncryptionException exception when algorithm cannot be created
     */
    protected GenericEncryptionAlgorithm(EncryptionEngine engine,
                                         BytesRepresentation bytesRepresentation,
                                         String encoding) throws EncryptionException {
        this.engine = engine;
        this.bytesRepresentation = bytesRepresentation;
        this.encoding = encoding;

        this.usesInitVector = false;
        this.blockSize = -1;
        this.ivFactory = null;
        this.ivOutputCombining = null;
    }

    @Override
    public byte[] encrypt(byte[] input) throws EncryptionException {
        if (input == null) {
            throw new IllegalArgumentException("Input data for encryption cannot be null!");
        }
        if (usesInitVector) {
            byte[] iv = getIv();
            byte[] encryptedBytes = engine.encrypt(input, iv);
            return ivOutputCombining.combine(iv, encryptedBytes);
        } else {
            return engine.encrypt(input, null);
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
        if (usesInitVector) {
            byte[][] ivAndCipherText = ivOutputCombining.split(input);
            if (ivAndCipherText == null || ivAndCipherText.length != 2) {
                throw new EncryptionException("Splitting of input into two parts during decryption produced wrong " +
                        "number of parts. Is the input or used implementation of CombiningSplitting correct?");
            }
            return engine.decrypt(ivAndCipherText[1], ivAndCipherText[0]);
        } else {
            return engine.decrypt(input, null);
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

    private byte[] getIv() {
        byte[] ivBytes = ivFactory.getBytes(blockSize);
        if (ivBytes.length != blockSize) {
            throw new IllegalArgumentException("Generated initialization vector has size " + ivBytes.length +
                    " bytes but must be size equal to block size " + blockSize + " bytes");
        }
        return ivBytes;
    }
}
