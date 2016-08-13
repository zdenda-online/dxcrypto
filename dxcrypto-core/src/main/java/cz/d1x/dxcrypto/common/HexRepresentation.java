package cz.d1x.dxcrypto.common;

import javax.xml.bind.DatatypeConverter;

/**
 * Implementation that represents byte arrays in HEX form.
 * That means every byte is simply converted to string. E.g. 0x3a = "3a"...
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public final class HexRepresentation implements BytesRepresentation {

    private static final boolean DEFAULT_USE_LOWER_CASE = true;

    private final boolean useLowerCase;

    /**
     * Creates a new instance of HEX representation that uses default lower-cased letters.
     */
    public HexRepresentation() {
        this(DEFAULT_USE_LOWER_CASE);
    }

    /**
     * Creates a new instance of HEX representation that uses given casing of letters.
     *
     * @param useLowerCase flag whether use lower cased letters (true) or upper cased (false)
     */
    public HexRepresentation(boolean useLowerCase) {
        this.useLowerCase = useLowerCase;
    }

    /**
     * {@inheritDoc}
     *
     * @param bytes bytes to be converted
     * @return HEX representation (lower case characters)
     * @throws IllegalArgumentException possible exception if input is null or cannot be converted
     */
    @Override
    public String toString(byte[] bytes) throws IllegalArgumentException {
        if (bytes == null) {
            throw new IllegalArgumentException("Input bytes cannot be null when converted to HEX");
        }
        try {
            return doCasing(DatatypeConverter.printHexBinary(bytes));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Input bytes cannot be converted to HEX", e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * @param hex HEX string input to be converted
     * @return byte array representation
     * @throws IllegalArgumentException possible exception if input is null or cannot be converted
     */
    @Override
    public byte[] toBytes(String hex) throws IllegalArgumentException {
        if (hex == null) {
            throw new IllegalArgumentException("Input HEX cannot be null when converted to bytes");
        }
        try {
            return DatatypeConverter.parseHexBinary(doCasing(hex));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Input HEX cannot be converted to bytes", e);
        }
    }

    private String doCasing(String result) {
        return useLowerCase ? result.toLowerCase() : result.toUpperCase();
    }
}
