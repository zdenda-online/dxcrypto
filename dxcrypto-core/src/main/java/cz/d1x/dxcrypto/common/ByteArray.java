package cz.d1x.dxcrypto.common;

/**
 * Utility class that wraps byte array that can later be used as generic.
 */
public class ByteArray {

    private byte[] value;

    public ByteArray(byte[] value) {
        this.value = value;
    }

    /**
     * Gets a value of wrapped bytes.
     *
     * @return wrapped bytes
     */
    public byte[] getValue() {
        return value;
    }
}
