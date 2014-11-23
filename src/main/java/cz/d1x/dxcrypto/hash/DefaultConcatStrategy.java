package cz.d1x.dxcrypto.hash;

/**
 * Default strategy for concatenation of input text and salt.
 * It puts one specific byte between input and salt.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see SaltingAdapter
 */
public class DefaultConcatStrategy implements ConcatStrategy {

    @Override
    public byte[] concatenate(byte[] input, byte[] salt) {
        byte[] out = new byte[input.length + salt.length + 1]; // 1 byte between input and salt
        System.arraycopy(input, 0, out, 0, input.length);
        out[input.length] = 0x27; // my favourite number:-)
        System.arraycopy(salt, 0, out, input.length + 1, salt.length);
        return out;
    }
}
