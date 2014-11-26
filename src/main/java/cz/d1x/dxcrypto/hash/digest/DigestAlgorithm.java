package cz.d1x.dxcrypto.hash.digest;

import cz.d1x.dxcrypto.Encoding;
import cz.d1x.dxcrypto.hash.HashingAlgorithm;
import cz.d1x.dxcrypto.hash.HashingException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Abstract class for hashing algorithm which uses {@link java.security.MessageDigest} for hashing.
 * <p/>
 * This class is immutable and can be considered thread safe. It is not allowed to extend this class to ensure it stays
 * that way.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public final class DigestAlgorithm implements HashingAlgorithm {

    private final String digestName;
    private final String encoding;

    /**
     * Creates a new instance with given encoding.
     *
     * @param encoding encoding used for strings
     */
    protected DigestAlgorithm(String digestName, String encoding) {
        Encoding.checkEncoding(encoding);
        this.encoding = encoding;

        try {
            MessageDigest.getInstance(digestName); // check whether it can be created
            this.digestName = digestName;
        } catch (NoSuchAlgorithmException ex) {
            throw new HashingException(ex);
        }
    }

    @Override
    public byte[] hash(byte[] input) throws HashingException {
        if (input == null) {
            throw new HashingException("Input data for hashing cannot be null");
        }
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(digestName);
        } catch (NoSuchAlgorithmException e) {
            throw new HashingException("Unable to get instance of digest " + digestName, e);
        }
        digest.reset();
        return digest.digest(input);
    }

    @Override
    public String hash(String input) throws HashingException {
        if (input == null) {
            throw new HashingException("Input data for hashing cannot be null");
        }
        byte[] textBytes = Encoding.getBytes(input, encoding);
        byte[] hash = hash(textBytes);
        return Encoding.toHex(hash);
    }
}
