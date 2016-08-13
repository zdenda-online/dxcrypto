package cz.d1x.dxcrypto.common;

/**
 * Drives how byte arrays should be represented in {@link String} instances (typically output of hashing and encryption
 * or input of decryption). It is common, that output hashes are in lower-cased HEX representation.
 * On the other hand, representation for encryption algorithm varies. It is valid to use any representation as Base64
 * seems to be more common because it uses less characters than HEX.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see HexRepresentation
 * @see Base64Representation
 */
public interface BytesRepresentation {

    /**
     * Converts given byte array to {@link String} in this representation.
     *
     * @param bytes bytes to be converted
     * @return String form
     */
    String toString(byte[] bytes);

    /**
     * Converts given {@link String} in this representation back to to byte array.
     *
     * @param string string to be converted
     * @return byte array form
     */
    byte[] toBytes(String string);
}
