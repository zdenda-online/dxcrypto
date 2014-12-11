package cz.d1x.dxcrypto.hash.digest;

import cz.d1x.dxcrypto.hash.RepeatingDecorator;
import cz.d1x.dxcrypto.hash.SaltingAdapter;

/**
 * <p>
 * Builder for SHA-512 hashing algorithm.
 * </p><p>
 * This algorithm should be sufficient for many cases (e.g. password hashing).
 * If you require slightly lower execution time, you can also use {@link SHA256Builder}.
 * </p><p>
 * You can make potential attacks harder if you use salt (e.g. by using {@link SaltingAdapter}).
 * You can also do repeated hashing by using {@link RepeatingDecorator} if higher execution time is not an issue for you.
 * </p><p>
 * This class is immutable and can be considered thread safe.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class SHA512Builder extends DigestAlgorithmBuilder {

    /**
     * Creates a new builder for MD5 hashing algorithm.
     */
    public SHA512Builder() {
    }

    @Override
    protected String getAlgorithm() {
        return "SHA-512";
    }
}
