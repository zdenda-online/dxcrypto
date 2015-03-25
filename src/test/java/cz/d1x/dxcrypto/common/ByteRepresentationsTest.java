package cz.d1x.dxcrypto.common;

import org.junit.Assert;
import org.junit.Test;

import java.io.UnsupportedEncodingException;

/**
 * Tests {@link BytesRepresentation} implementations.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class ByteRepresentationsTest {

    /**
     * Tests Base64 representation.
     */
    @Test
    public void base64Representation() throws UnsupportedEncodingException {
        byte[] bytes = "this-Is_funnY132".getBytes(Encoding.DEFAULT);

        BytesRepresentation representation = new Base64Representation();
        String actual = representation.toString(bytes);
        Assert.assertEquals("dGhpcy1Jc19mdW5uWTEzMg==", actual);
    }

    /**
     * Tests HEX representation.
     */
    @Test
    public void hexRepresentation() throws UnsupportedEncodingException {
        byte[] bytes = "this-Is_funnY132".getBytes(Encoding.DEFAULT);

        BytesRepresentation representation = new HexRepresentation();
        String actual = representation.toString(bytes);
        Assert.assertEquals(slowConvert(bytes), actual);
    }

    /**
     * This conversion is very slow but will do fine for testing whether algorithm works well.
     */
    private static String slowConvert(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
