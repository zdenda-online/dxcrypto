package cz.d1x.crypto.hash.impl;

import cz.d1x.crypto.hash.HashingAlgorithm;

/**
 * {@link HashingAlgorithm} implementation representing SHA-512 algorithm.
 * This class is immutable and can be considered thread safe.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class SHA512 extends DigestHashingAlgorithm {

    /**
     * Creates a new instance that uses {@link HashingAlgorithm#DEFAULT_ENCODING} for string encoding.
     */
    public SHA512() {
        super();
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
