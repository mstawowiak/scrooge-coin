package com.github.mstawowiak.blockchain.scroogecoin.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class HashCalculcator {

    /**
     * Returns bytes of hash calculated using SHA-256 algorithm for payload
     *
     * @param payload payload to hash
     * @return bytes of SHA-512 hash for given payload
     */
    public static byte[] calculateSHA256(String payload) {
        return calculate(payload, MessageDigestAlgorithm.SHA256);
    }

    /**
     * Returns bytes of hash calculated using {@link MessageDigestAlgorithm} for given payload
     *
     * @param payload payload to hash
     * @param algorithm message digest algorithm
     * @return bytes of hash for given payload, calculated with given algorithm
     */
    public static byte[] calculate(String payload, MessageDigestAlgorithm algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm.getAlgorithm());
            md.update(payload.getBytes());

            return md.digest();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Required crypto algorithm '" + algorithm + "' is not supported", ex);
        }
    }

    public enum MessageDigestAlgorithm {

        MD2("MD2"),
        MD5("MD5"),
        SHA1("SHA-1"),
        SHA256("SHA-256"),
        SHA384("SHA-384"),
        SHA512("SHA-512");

        /**
         * Algorithm name as defined in
         * {@link MessageDigest#getInstance(String)}
         */
        private final String algorithm;

        MessageDigestAlgorithm(final String algorithm) {
            this.algorithm = algorithm;
        }

        public String getAlgorithm() {
            return this.algorithm;
        }
    }

    private HashCalculcator() {
    }
}
