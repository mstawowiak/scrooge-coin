package com.github.mstawowiak.blockchain.scroogecoin.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

@SuppressWarnings("PMD.AvoidPrintStackTrace")
public final class Crypto {

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    /**
     * @return true is {@code signature} is a valid digital signature of {@code message} under the
     *         key {@code pubKey}. Internally, this uses RSA signature, but the student does not
     *         have to deal with any of the implementation details of the specific signature
     *         algorithm
     */
    public static boolean verifySignature(PublicKey pubKey, byte[] message, byte[] signature) {
        Signature sig = initSignature();
        try {
            sig.initVerify(pubKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        try {
            sig.update(message);
            return sig.verify(signature);
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * @return digital signature of {@code message} under the key {@code privateKey} using RSA
     */
    public static byte[] sign(PrivateKey privateKey, byte[] message) {
        Signature sig = initSignature();
        try {
            sig.initSign(privateKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        try {
            sig.update(message);
            return sig.sign();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }

    private static Signature initSignature() {
        Signature sig = null;
        try {
            sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return sig;
    }

    private Crypto() {
    }
}
