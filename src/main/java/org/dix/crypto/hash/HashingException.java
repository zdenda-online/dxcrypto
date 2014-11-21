package org.dix.crypto.hash;

/**
 * Wrapper for exceptions during hashing.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class HashingException extends RuntimeException {

    /**
     * Creates a new hashing exception.
     *
     * @param message message of exception
     */
    public HashingException(String message) {
        this(message, null);
    }

    /**
     * Creates a new hashing exception.
     *
     * @param cause cause of exception
     */
    public HashingException(Throwable cause) {
        this("Hashing failed due to: " + cause.getMessage(), cause);
    }

    /**
     * Creates a new hashing exception.
     *
     * @param message message of exception
     * @param cause   cause of exception
     */
    public HashingException(String message, Throwable cause) {
        super(message, cause);
    }
}
