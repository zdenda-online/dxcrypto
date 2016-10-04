package cz.d1x.dxcrypto.encryption.bc;

import cz.d1x.dxcrypto.encryption.EncryptionEngine;
import cz.d1x.dxcrypto.encryption.EncryptionException;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Implementation of encryption engine that uses Bouncy Castle implementations for symmetric encryption.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class BouncyCastleSymmetricEngine implements EncryptionEngine {

    private final Class<? extends BlockCipher> blockCipherClass;
    private final KeyParameter keyParam;

    public BouncyCastleSymmetricEngine(Class<? extends BlockCipher> blockCipherClass, KeyParameter keyParam) {
        this.blockCipherClass = blockCipherClass;
        this.keyParam = keyParam;
    }

    @Override
    public byte[] encrypt(byte[] input, byte[] initVector) throws EncryptionException {
        return doOperation(input, initVector, true);
    }

    @Override
    public byte[] decrypt(byte[] input, byte[] initVector) throws EncryptionException {
        return doOperation(input, initVector, false);
    }

    private byte[] doOperation(byte[] input, byte[] initVector, boolean isEncrypt) {
        CipherParameters params = new ParametersWithIV(keyParam, initVector);
        BlockCipherPadding padding = new PKCS7Padding();
        BlockCipher blockCipher;
        try {
            blockCipher = blockCipherClass.newInstance();
        } catch (InstantiationException | IllegalAccessException e) {
            throw new EncryptionException("Encryption fails", e);
        }
        BlockCipher engine = new CBCBlockCipher(blockCipher);
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(engine, padding);
        cipher.init(isEncrypt, params);

        byte[] output = new byte[cipher.getOutputSize(input.length)];
        int length = cipher.processBytes(input, 0, input.length, output, 0);
        try {
            length += cipher.doFinal(output, length);
        } catch (InvalidCipherTextException e) {
            throw new EncryptionException("Encryption fails", e);
        }

        // Remove output padding
        byte[] out = new byte[length];
        System.arraycopy(output, 0, out, 0, length);
        return out;
    }

}
