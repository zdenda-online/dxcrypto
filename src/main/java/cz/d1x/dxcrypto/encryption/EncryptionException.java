package cz.d1x.dxcrypto.encryption;

/**
 * Wrapper for exceptions during encryption or decryption.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class EncryptionException extends RuntimeException {

    /**
     * Creates a new encryption exception.
     *
     * @param message message of exception
     * @param cause   nested cause of exception
     */
    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Creates a new encryption exception.
     *
     * @param message message of exception
     */
    public EncryptionException(String message) {
        super(message);
    }
}
