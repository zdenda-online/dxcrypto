package cz.d1x.dxcrypto.common;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;

/**
 * Utilities for internal operations with encoding.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class Encoding {

    public static final String DEFAULT = "UTF-8";

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
     * Converts given {@link String} to byte array representation using {@link #DEFAULT}.
     *
     * @param text text to be converted
     * @return byte array representation
     * @throws IllegalArgumentException possible exception if text is null or encoding is not supported
     */
    public static byte[] getBytes(String text) {
        return getBytes(text, DEFAULT);
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
     * Converts given byte array to {@link String} using {@link #DEFAULT}.
     *
     * @param text text bytes to be converted
     * @return encoded text
     * @throws IllegalArgumentException possible exception if text bytes are null or encoding is not supported
     */
    public static String getString(byte[] text) {
        return getString(text, DEFAULT);
    }
}
