package cz.d1x.dxcrypto.hash.digest;

import cz.d1x.dxcrypto.common.BytesRepresentation;
import cz.d1x.dxcrypto.common.Encoding;
import cz.d1x.dxcrypto.hash.HashingAlgorithm;
import cz.d1x.dxcrypto.hash.HashingException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * <p>
 * Abstract class for hashing algorithm which uses {@link java.security.MessageDigest} for hashing.
 * </p><p>
 * This class is immutable and can be considered thread safe. It is not allowed to extend this class to ensure it stays
 * that way.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public final class DigestAlgorithm implements HashingAlgorithm {

    private final MessageDigest digest;
    private final BytesRepresentation bytesRepresentation;
    private final String encoding;

    /**
     * Creates a new instance with given encoding.
     *
     * @param digestName          name of the digest
     * @param bytesRepresentation representation of byte arrays in String
     * @param encoding            encoding used for strings
     */
    protected DigestAlgorithm(String digestName, BytesRepresentation bytesRepresentation, String encoding) {
        Encoding.checkEncoding(encoding);
        this.bytesRepresentation = bytesRepresentation;
        this.encoding = encoding;

        try {
            this.digest = MessageDigest.getInstance(digestName);
        } catch (NoSuchAlgorithmException ex) {
            throw new HashingException(ex);
        }
    }

    @Override
    public byte[] hash(byte[] input) throws HashingException {
        if (input == null) {
            throw new HashingException("Input data for hashing cannot be null");
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
        return bytesRepresentation.toString(hash);
    }
}
