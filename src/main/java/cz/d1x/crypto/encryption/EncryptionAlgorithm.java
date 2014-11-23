package cz.d1x.crypto.encryption;

import cz.d1x.crypto.encryption.crypto.AES;
import cz.d1x.crypto.encryption.crypto.TripleDES;

/**
 * Interface for algorithms that are able to encrypt given input and decrypt it afterwards.
 * <p/>
 * It is recommended that implementations of symmetric algorithms will use initialization vector. Due to simplicity,
 * decrypt methods does not require this IV, because it is expected that IV will be part of the encrypted message
 * or stored within instance itself. If you choose any of these options, be sure to provide the information (in javadoc)
 * how your implementation should be used. Typically when you store IV in the instance, you should create a new
 * instance for every encrypted message to be sure it uses different IV.
 * <p/>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see cz.d1x.crypto.encryption.crypto.CryptoSymmetricAlgorithm
 * @see AES
 * @see TripleDES
 */
public interface EncryptionAlgorithm {

    /**
     * Encrypts specified array of bytes.
     *
     * @param input input bytes to be encrypted
     * @return encrypted bytes
     * @throws EncryptionException possible exception when encryption fails
     */
    byte[] encrypt(byte[] input) throws EncryptionException;

    /**
     * Encrypts specified input text.
     *
     * @param input input text to be encrypted
     * @return encrypted text
     * @throws EncryptionException possible exception when encryption fails
     */
    String encrypt(String input) throws EncryptionException;

    /**
     * Decrypts specified array of bytes.
     *
     * @param input input bytes to be decrypted
     * @return decrypted bytes
     * @throws EncryptionException possible exception when decryption fails
     */
    byte[] decrypt(byte[] input) throws EncryptionException;

    /**
     * Decrypts specified input text using default UTF-8 encoding.
     *
     * @param input input text to be decrypted
     * @return decrypted text
     * @throws EncryptionException possible exception when decryption fails
     */
    String decrypt(String input) throws EncryptionException;
}
