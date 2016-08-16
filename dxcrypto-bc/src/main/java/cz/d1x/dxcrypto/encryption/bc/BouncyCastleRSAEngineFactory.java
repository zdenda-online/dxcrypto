package cz.d1x.dxcrypto.encryption.bc;

import cz.d1x.dxcrypto.encryption.AsymmetricEncryptionEngineFactory;
import cz.d1x.dxcrypto.encryption.EncryptionEngine;
import cz.d1x.dxcrypto.encryption.key.RSAKeyParams;
import org.bouncycastle.crypto.params.RSAKeyParameters;

/**
 * Factory that provides {@link EncryptionEngine} implementation for RSA algorithm from Bouncy Castle.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class BouncyCastleRSAEngineFactory implements AsymmetricEncryptionEngineFactory<RSAKeyParams, RSAKeyParams> {

    @Override
    public EncryptionEngine newEngine(RSAKeyParams publicKey, RSAKeyParams privateKey) {
        RSAKeyParameters pubKey = null, privKey = null;
        if (publicKey != null) {
            pubKey = new RSAKeyParameters(false, publicKey.getModulus(), publicKey.getExponent());
        }
        if (privateKey != null) {
            privKey = new RSAKeyParameters(true, privateKey.getModulus(), privateKey.getExponent());
        }
        return new BouncyCastleRSAEngine(pubKey, privKey);
    }
}
