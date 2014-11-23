package cz.d1x.dxcrypto.hash.digest;

import cz.d1x.dxcrypto.Encoding;
import cz.d1x.dxcrypto.hash.RepeatingDecorator;

/**
 * MD5 hashing algorithm.
 * <p/>
 * More than 10 years, it is <strong>NOT</strong> recommended to use this algorithm.
 * If you can choose, go with some stronger function (e.g. SHA-256 or SHA-512).
 * <p/>
 * You can make potential attacks harder if you use salt (e.g. by using {@link cz.d1x.dxcrypto.hash.DefaultConcatStrategy}).
 * You can also do repeated hashing by using {@link RepeatingDecorator} if higher execution time is not an issue for you.
 * <p/>
 * This class is immutable and can be considered thread safe.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class MD5 extends DigestHashingAlgorithm {

    /**
     * Creates a new instance that uses {@link cz.d1x.dxcrypto.Encoding#DEFAULT_ENCODING} for string encoding.
     */
    public MD5() {
        super(Encoding.DEFAULT_ENCODING);
    }

    /**
     * Creates a new instance that uses given encoding for strings.
     *
     * @param encoding encoding to be used
     */
    public MD5(String encoding) {
        super(encoding);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected String getDigestName() {
        return "MD5";
    }
}
