package cz.d1x.dxcrypto.common;

/**
 * <p>
 * Factory that is able to provide byte arrays in given length.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public interface ByteArrayFactory {

    /**
     * Creates a byte array of given size.
     * If passed size is 0, it creates empty byte array.
     *
     * @param size size of desired byte array
     * @return byte array of given size
     */
    byte[] getBytes(int size);
}
