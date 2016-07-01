package cz.d1x.dxcrypto.common;

import java.security.SecureRandom;

/**
 * <p>
 * Implementation of {@link ByteArrayFactory} that generates random byte arrays.
 * It uses {@link SecureRandom} for generation of arrays.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class RandomByteArrayFactory implements ByteArrayFactory {

    private final SecureRandom random = new SecureRandom(); // is thread-safe

    @Override
    public byte[] getBytes(int size) {
        if (size == 0) {
            return new byte[0];
        }
        byte[] out = new byte[size];
        random.nextBytes(out);
        return out;
    }
}
