package cz.d1x.dxcrypto.hash;

import cz.d1x.dxcrypto.hash.digest.MD5Builder;
import cz.d1x.dxcrypto.hash.digest.SHA1Builder;
import cz.d1x.dxcrypto.hash.digest.SHA256Builder;
import cz.d1x.dxcrypto.hash.digest.SHA512Builder;

/**
 * Factory that provides available hashing algorithms.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class HashingAlgorithms {

    /**
     * Creates a new builder for MD5 hashing algorithm.
     */
    public static MD5Builder md5() {
        return new MD5Builder();
    }

    /**
     * Creates a new builder for SHA-1 hashing algorithm.
     */
    public static SHA1Builder sha1() {
        return new SHA1Builder();
    }

    /**
     * Creates a new builder for SHA-256 hashing algorithm.
     */
    public static SHA256Builder sha256() {
        return new SHA256Builder();
    }

    /**
     * Creates a new builder for SHA-512 hashing algorithm.
     */
    public static SHA512Builder sha512() {
        return new SHA512Builder();
    }
}
