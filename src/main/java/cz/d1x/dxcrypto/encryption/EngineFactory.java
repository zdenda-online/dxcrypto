package cz.d1x.dxcrypto.encryption;

/**
 * Created by d1x on 26.7.16.
 */
public interface EngineFactory {

    EncryptionEngine newEngine(byte[] keyPassword, byte[] keySalt, int keyHashIterations, int keySize);
}
