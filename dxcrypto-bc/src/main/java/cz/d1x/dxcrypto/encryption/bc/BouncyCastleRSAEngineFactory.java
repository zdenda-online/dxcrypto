package cz.d1x.dxcrypto.encryption.bc;

import cz.d1x.dxcrypto.encryption.AsymmetricEncryptionEngineFactory;
import cz.d1x.dxcrypto.encryption.EncryptionEngine;
import cz.d1x.dxcrypto.encryption.key.RSAKeyParams;
import org.bouncycastle.crypto.params.RSAKeyParameters;

public class BouncyCastleRSAEngineFactory implements AsymmetricEncryptionEngineFactory<RSAKeyParams, RSAKeyParams> {

    @Override
    public EncryptionEngine newEngine(RSAKeyParams publicKey, RSAKeyParams privateKey) {
        RSAKeyParameters pubKey = null, privKey = null;
        if (publicKey != null) {
            pubKey = new RSAKeyParameters(true, publicKey.getModulus(), publicKey.getExponent());
        }
        if (privateKey != null) {
            privKey = new RSAKeyParameters(false, privateKey.getModulus(), privateKey.getExponent());
        }
        return new BouncyCastleRSAEngine(pubKey, privKey);
    }
}
