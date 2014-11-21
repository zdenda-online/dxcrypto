package org.dix.crypto.hash.impl;

import org.dix.crypto.hash.HashingAlgorithm;
import org.dix.crypto.hash.HashingException;

import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Abstract class for hashing algorithm which uses {@link java.security.MessageDigest} for hashing.
 * This class is immutable and can be considered thread safe.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public abstract class DigestHashingAlgorithm implements HashingAlgorithm {

    protected final MessageDigest digest;
    protected final String encoding;

    /**
     * Creates a new instance with default encoding.
     */
    protected DigestHashingAlgorithm() {
        this(DEFAULT_ENCODING);
    }

    /**
     * Creates a new instance with given encoding.
     *
     * @param encoding encoding used for strings
     */
    protected DigestHashingAlgorithm(String encoding) {
        if (!Charset.isSupported(encoding)) {
            throw new HashingException("Given encoding " + encoding + " is not supported");
        }
        this.encoding = encoding;

        try {
            String digestName = getDigestName();
            this.digest = MessageDigest.getInstance(digestName);
        } catch (NoSuchAlgorithmException ex) {
            throw new HashingException(ex);
        }
    }

    /**
     * Gets name of concrete digest used for its initialization.
     * This name is used for {@link java.security.MessageDigest#getInstance(String)})
     *
     * @return name of the digest
     */
    protected abstract String getDigestName();

    @Override
    public byte[] hash(byte[] input) throws HashingException {
        if (input == null) {
            throw new HashingException("Input data are null!");
        }
        digest.reset();
        return digest.digest(input);
    }

    @Override
    public String hash(String input) throws HashingException {
        if (input == null) {
            throw new HashingException("Input data are null!");
        }
        try {
            byte[] textBytes = input.getBytes(encoding);
            byte[] hash = hash(textBytes);
            return DatatypeConverter.printHexBinary(hash).toLowerCase();
        } catch (UnsupportedEncodingException e) {
            throw new HashingException(e);
        }
    }
}
