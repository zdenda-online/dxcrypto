package cz.d1x.dxcrypto.encryption;

public interface EncryptionEngine {

    byte[] encrypt(byte[] input, byte[] initVector);

    byte[] decrypt(byte[] input, byte[] initVector);

}
