package cz.d1x.dxcrypto.encryption;

import cz.d1x.dxcrypto.encryption.crypto.AESBuilder;
import cz.d1x.dxcrypto.encryption.crypto.RSABuilder;
import cz.d1x.dxcrypto.encryption.crypto.TripleDESBuilder;

/**
 * Interface for algorithms that are able to encrypt given input and decrypt it afterwards.
 * Note that it is strongly recommended that implementations will be <strong>immutable</strong>.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see AESBuilder
 * @see TripleDESBuilder
 * @see RSABuilder
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
