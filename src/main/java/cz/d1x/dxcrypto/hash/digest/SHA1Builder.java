package cz.d1x.dxcrypto.hash.digest;

import cz.d1x.dxcrypto.hash.RepeatingDecorator;
import cz.d1x.dxcrypto.hash.SaltingAdapter;

/**
 * Builder for SHA-1 hashing algorithm.
 * <p/>
 * Even when this algorithm is stronger than {@link MD5Builder}, it has also its weaknesses.
 * If you can choose, go with some stronger function (e.g. SHA-256 or SHA-512).
 * <p/>
 * You can make potential attacks harder if you use salt (e.g. by using {@link SaltingAdapter}).
 * You can also do repeated hashing by using {@link RepeatingDecorator} if higher execution time is not an issue for you.
 * <p/>
 * This class is immutable and can be considered thread safe.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class SHA1Builder extends DigestAlgorithmBuilder {

    /**
     * Creates a new builder for MD5 hashing algorithm.
     */
    public SHA1Builder() {
    }

    @Override
    protected String getAlgorithm() {
        return "SHA-1";
    }
}
