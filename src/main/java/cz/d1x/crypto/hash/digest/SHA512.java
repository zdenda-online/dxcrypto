package cz.d1x.crypto.hash.digest;

import cz.d1x.crypto.Encoding;
import cz.d1x.crypto.hash.RepeatingDecorator;

/**
 * SHA-512 hashing algorithm.
 * <p/>
 * This algorithm should be sufficient for many cases (e.g. password hashing).
 * If you require slightly lower execution time, you can also use {@link SHA256}.
 * <p/>
 * You can make potential attacks harder if you use salt (e.g. by using {@link cz.d1x.crypto.hash.DefaultConcatStrategy}).
 * You can also do repeated hashing by using {@link RepeatingDecorator} if higher execution time is not an issue for you.
 * <p/>
 * This class is immutable and can be considered thread safe.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class SHA512 extends DigestHashingAlgorithm {

    /**
     * Creates a new instance that uses {@link cz.d1x.crypto.Encoding#DEFAULT_ENCODING} for string encoding.
     */
    public SHA512() {
        super(Encoding.DEFAULT_ENCODING);
    }

    /**
     * Creates a new instance that uses given encoding for strings.
     *
     * @param encoding encoding to be used
     */
    public SHA512(String encoding) {
        super(encoding);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected String getDigestName() {
        return "SHA-512";
    }
}
