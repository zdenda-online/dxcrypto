package org.dix.crypto.hash.impl;

import org.dix.crypto.hash.HashingAlgorithm;

/**
 * {@link HashingAlgorithm} implementation representing SHA-256 algorithm.
 * This class is immutable and can be considered thread safe.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class SHA256 extends DigestHashingAlgorithm {

    /**
     * Creates a new instance that uses {@link HashingAlgorithm#DEFAULT_ENCODING} for string encoding.
     */
    public SHA256() {
        super();
    }

    /**
     * Creates a new instance that uses given encoding for strings.
     *
     * @param encoding encoding to be used
     */
    public SHA256(String encoding) {
        super(encoding);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected String getDigestName() {
        return "SHA-256";
    }
}
