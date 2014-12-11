package cz.d1x.dxcrypto.hash.digest;

import cz.d1x.dxcrypto.hash.RepeatingDecorator;
import cz.d1x.dxcrypto.hash.SaltingAdapter;

/**
 * <p>
 * Builder for MD5 hashing algorithm.
 * </p><p>
 * More than 10 years, it is <strong>NOT</strong> recommended to use this algorithm.
 * If you can choose, go with some stronger function (e.g. SHA-256 or SHA-512).
 * </p><p>
 * You can make potential attacks harder if you use salt (e.g. by using {@link SaltingAdapter}).
 * You can also do repeated hashing by using {@link RepeatingDecorator} if higher execution time is not an issue for you.
 * </p><p>
 * This class is immutable and can be considered thread safe.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class MD5Builder extends DigestAlgorithmBuilder {

    /**
     * Creates a new builder for MD5 hashing algorithm.
     */
    public MD5Builder() {
    }

    @Override
    protected String getAlgorithm() {
        return "MD5";
    }
}
