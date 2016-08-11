package cz.d1x.dxcrypto.encryption;

/**
 * Interface for encryption engines that are able to encrypt and decrypt inputs.
 * Note that implementations should be immutable (should not change its internal state by
 * {@link #encrypt(byte[], byte[])} and {@link #decrypt(byte[], byte[])} methods.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public interface EncryptionEngine {

    /**
     * Encrypts given input and using given initialization vector (if needed).
     *
     * @param input      input to be encrypted
     * @param initVector initialization vector for encryption if needed (can be null)
     * @return encrypted input
     */
    byte[] encrypt(byte[] input, byte[] initVector);

    /**
     * Decrypts given input using given initialization vector (if needed)
     *
     * @param input      input to be decrypted
     * @param initVector initialization vector for decryption if needed (can be null)
     * @return decrypted input
     */
    byte[] decrypt(byte[] input, byte[] initVector);

}
