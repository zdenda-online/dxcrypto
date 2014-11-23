package cz.d1x.dxcrypto;

import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;

/**
 * Utilities for internal operations with encoding.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class Encoding {

    public static final String UTF_8 = "UTF-8"; // default encoding

    /**
     * Converts given byte array into {@link String} in HEX representation.
     *
     * @param bytes bytes to be converted
     * @return HEX representation (lower case characters)
     * @throws IllegalArgumentException possible exception if input is null or cannot be converted
     */
    public static String toHex(byte[] bytes) throws IllegalArgumentException {
        if (bytes == null) {
            throw new IllegalArgumentException("Input bytes cannot be null when converted to HEX format");
        }
        try {
            return DatatypeConverter.printHexBinary(bytes).toLowerCase();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Input HEX cannot be converted to bytes", e);
        }
    }

    /**
     * Converts given {@link String} in HEX representation to byte array representation.
     *
     * @param hex HEX string input to be converted
     * @return byte array representation
     * @throws IllegalArgumentException possible exception if input is null or cannot be converted
     */
    public static byte[] fromHex(String hex) throws IllegalArgumentException {
        if (hex == null) {
            throw new IllegalArgumentException("Input HEX cannot be null when converted to bytes");
        }
        try {
            return DatatypeConverter.parseHexBinary(hex.toLowerCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Input HEX cannot be converted to bytes", e);
        }
    }

    /**
     * Checks whether given encoding (name) is supported.
     *
     * @param encoding encoding to check
     * @throws IllegalArgumentException possible exception if encoding is null or not supported
     */
    public static void checkEncoding(String encoding) throws IllegalArgumentException {
        boolean isSupported;
        try {
            isSupported = Charset.isSupported(encoding);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Given encoding " + encoding + " is not supported");
        }
        if (!isSupported) {
            throw new IllegalArgumentException("Given encoding " + encoding + " is not supported");
        }
    }

    /**
     * Converts given {@link String} with given encoding to byte array representation.
     * It is recommended to check your encoding via {@link #checkEncoding(String)}.
     *
     * @param text     text to be converted
     * @param encoding encoding of text
     * @return byte array representation
     * @throws IllegalArgumentException possible exception if text is null or encoding is not supported
     */
    public static byte[] getBytes(String text, String encoding) throws IllegalArgumentException {
        if (text == null) {
            throw new IllegalArgumentException("Given text cannot be null");
        }
        try {
            return text.getBytes(encoding);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException("Given encoding " + encoding + " is not supported");
        }
    }

    /**
     * Converts given {@link String} to byte array representation using {@link #UTF_8}.
     *
     * @param text text to be converted
     * @return byte array representation
     * @throws IllegalArgumentException possible exception if text is null or encoding is not supported
     */
    public static byte[] getBytes(String text) {
        return getBytes(text, UTF_8);
    }

    /**
     * Converts given byte array to {@link String} with given encoding.
     * It is recommended to check your encoding via {@link #checkEncoding(String)}.
     *
     * @param text     text bytes to be converted
     * @param encoding encoding for output
     * @return encoded text
     * @throws IllegalArgumentException possible exception if text bytes are null or encoding is not supported
     */
    public static String getString(byte[] text, String encoding) throws IllegalArgumentException {
        if (text == null) {
            throw new IllegalArgumentException("Given text bytes cannot be null");
        }
        try {
            return new String(text, encoding);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException("Given encoding " + encoding + " is not supported");
        }
    }

    /**
     * Converts given byte array to {@link String} using {@link #UTF_8}.
     *
     * @param text text bytes to be converted
     * @return encoded text
     * @throws IllegalArgumentException possible exception if text bytes are null or encoding is not supported
     */
    public static String getString(byte[] text) {
        return getString(text, UTF_8);
    }
}
