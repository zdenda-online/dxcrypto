package cz.d1x.dxcrypto.hash;

/**
 * Factory that provides builders for available hashing algorithms.
 * Create a new builder and when you are done with parameters, call {@link HashingAlgorithmBuilder#build()}
 * to retrieve immutable {@link HashingAlgorithm} instance.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class HashingAlgorithms {

    /**
     * Creates a new builder for MD5 hashing algorithm.
     * <p>
     * More than 10 years, it is <strong>NOT</strong> recommended to use this algorithm.
     * If you can choose, go with some stronger function (e.g. SHA-256 or SHA-512).
     * </p>
     *
     * @return builder for MD5
     */
    public static HashingAlgorithmBuilder md5() {
        return new DigestAlgorithmBuilder("MD5");
    }

    /**
     * Creates a new builder for SHA-1 hashing algorithm.
     * <p>
     * This algorithm is stronger than MD5 but it has also its weaknesses.
     * If you can choose, go with some stronger function (e.g. SHA-256 or SHA-512).
     * </p>
     *
     * @return builder for SHA-1
     */
    public static HashingAlgorithmBuilder sha1() {
        return new DigestAlgorithmBuilder("SHA-1");
    }

    /**
     * Creates a new builder for SHA-256 hashing algorithm.
     * <p>
     * This algorithm should be sufficient for many cases (e.g. password hashing).
     * If slightly higher execution time is not an issue for you, you can also use stronger SHA-512.
     * </p>
     *
     * @return builder for SHA-256
     */
    public static HashingAlgorithmBuilder sha256() {
        return new DigestAlgorithmBuilder("SHA-256");
    }

    /**
     * Creates a new builder for SHA-512 hashing algorithm.
     * <p>
     * This algorithm should be sufficient for many cases (e.g. password hashing).
     * If you need slightly lower execution time, you can also use SHA-256.
     * </p>
     *
     * @return builder for SHA-512
     */
    public static HashingAlgorithmBuilder sha512() {
        return new DigestAlgorithmBuilder("SHA-512");
    }
}
