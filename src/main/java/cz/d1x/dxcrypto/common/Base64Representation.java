package cz.d1x.dxcrypto.common;

import javax.xml.bind.DatatypeConverter;

/**
 * Implementation that represents byte arrays in Base64 form.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class Base64Representation implements BytesRepresentation {

    /**
     * Creates a new instance of Base64 representation.
     */
    public Base64Representation() {
    }

    /**
     * {@inheritDoc}
     *
     * @param bytes bytes to be converted
     * @return Base64 representation
     * @throws IllegalArgumentException possible exception if input is null or cannot be converted
     */
    @Override
    public String toString(byte[] bytes) throws IllegalArgumentException {
        if (bytes == null) {
            throw new IllegalArgumentException("Input bytes cannot be null when converted to Base64");
        }
        try {
            return DatatypeConverter.printBase64Binary(bytes);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Input bytes cannot be converted to Base64", e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * @param base64 Base64 string input to be converted
     * @return byte array representation
     * @throws IllegalArgumentException possible exception if input is null or cannot be converted
     */
    @Override
    public byte[] toBytes(String base64) throws IllegalArgumentException {
        if (base64 == null) {
            throw new IllegalArgumentException("Input Base64 cannot be null when converted to bytes");
        }
        try {
            return DatatypeConverter.parseBase64Binary(base64);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Input Base64 cannot be converted to bytes", e);
        }
    }
}
