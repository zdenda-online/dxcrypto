package cz.d1x.dxcrypto.encryption.bc;

import cz.d1x.dxcrypto.encryption.EncryptionEngine;
import cz.d1x.dxcrypto.encryption.EncryptionException;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;

public class BouncyCastleRSAEngine implements EncryptionEngine {

    private final RSAKeyParameters publicKey;
    private final RSAKeyParameters privateKey;

    public BouncyCastleRSAEngine(RSAKeyParameters publicKey, RSAKeyParameters privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public byte[] encrypt(byte[] input, byte[] initVector) throws EncryptionException {
        return doOperation(input, true);
    }

    public byte[] decrypt(byte[] input, byte[] initVector) throws EncryptionException {
        return doOperation(input, true);
    }

    private byte[] doOperation(byte[] input, boolean isEncrypt) {
        AsymmetricBlockCipher cipher = new OAEPEncoding(new RSAEngine());
        RSAKeyParameters key = isEncrypt ? publicKey : privateKey;
        cipher.init(isEncrypt, key);
        try {
            return cipher.processBlock(input, 0, input.length);
        } catch (InvalidCipherTextException e) {
            throw new EncryptionException("Encryption fails", e);
        }
    }
}
