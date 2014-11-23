package cz.d1x.dxcrypto.hash;

import cz.d1x.dxcrypto.Encoding;
import cz.d1x.dxcrypto.hash.digest.MD5;
import cz.d1x.dxcrypto.hash.digest.SHA1;
import cz.d1x.dxcrypto.hash.digest.SHA256;
import cz.d1x.dxcrypto.hash.digest.SHA512;

/**
 * Factory that provides available hashing algorithms.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class HashingAlgorithms {

    /**
     * Creates a new MD5 algorithm that uses {@link Encoding#UTF_8} for string encoding.
     */
    public static MD5 md5() {
        return new MD5();
    }

    /**
     * Creates a new instance that uses given encoding for strings.
     */
    public static MD5 md5(String encoding) {
        return new MD5(encoding);
    }

    /**
     * Creates a new SHA-1 algorithm that uses {@link Encoding#UTF_8} for string encoding.
     */
    public static SHA1 sha1() {
        return new SHA1();
    }

    /**
     * Creates a new SHA-1 algorithm that uses given encoding for strings.
     */
    public static SHA1 sha1(String encoding) {
        return new SHA1(encoding);
    }

    /**
     * Creates a new SHA-256 algorithm that uses {@link Encoding#UTF_8} for string encoding.
     */
    public static SHA256 sha256() {
        return new SHA256();
    }

    /**
     * Creates a new SHA-256 algorithm that uses given encoding for strings.
     */
    public static SHA256 sha256(String encoding) {
        return new SHA256(encoding);
    }

    /**
     * Creates a new SHA-512 algorithm that uses {@link Encoding#UTF_8} for string encoding.
     */
    public static SHA512 sha512() {
        return new SHA512();
    }

    /**
     * Creates a new SHA-512 algorithm that uses given encoding for strings.
     */
    public static SHA512 sha512(String encoding) {
        return new SHA512(encoding);
    }
}
