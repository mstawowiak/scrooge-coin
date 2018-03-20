package com.github.mstawowiak.blockchain.scroogecoin;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@SuppressWarnings({"PMD.UseArraysAsList", "PMD.ForLoopCanBeForeach"})
public class Transaction {

    /** hash of the transaction, its unique id */
    private byte[] hash;
    private final List<Input> inputs;
    private final List<Output> outputs;

    public class Input {
        /** hash of the Transaction whose output is being used */
        public byte[] prevTxHash;
        /** used output's index in the previous transaction */
        public int outputIndex;
        /** the signature produced to check validity */
        public byte[] signature;

        public Input(byte[] prevHash, int index) {
            if (prevHash == null) {
                prevTxHash = null; //NOPMD - NullAssignment
            } else {
                prevTxHash = Arrays.copyOf(prevHash, prevHash.length);
            }
            outputIndex = index;
        }

        public void addSignature(byte[] sig) {
            if (sig == null) {
                signature = null; //NOPMD - NullAssignment
            } else {
                signature = Arrays.copyOf(sig, sig.length);
            }
        }
    }

    public class Output {
        /** value in bitcoins of the output */
        public double value;
        /** the address or public key of the recipient */
        public PublicKey address;

        public Output(double val, PublicKey addr) {
            value = val;
            address = addr;
        }
    }

    public Transaction() {
        inputs = new ArrayList<>();
        outputs = new ArrayList<>();
    }

    public Transaction(Transaction tx) {
        hash = tx.hash.clone();
        inputs = new ArrayList<>(tx.inputs);
        outputs = new ArrayList<>(tx.outputs);
    }

    public void addInput(byte[] prevTxHash, int outputIndex) {
        Input in = new Input(prevTxHash, outputIndex);
        inputs.add(in);
    }

    public void addOutput(double value, PublicKey address) {
        Output op = new Output(value, address);
        outputs.add(op);
    }

    public void removeInput(int index) {
        inputs.remove(index);
    }

    public void removeInput(UTXO ut) {
        for (int i = 0; i < inputs.size(); i++) {
            Input in = inputs.get(i);
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
            if (utxo.equals(ut)) {
                inputs.remove(i);
                return;
            }
        }
    }

    public byte[] getRawDataToSign(int index) {
        // ith input and all outputs
        if (index > inputs.size()) {
            return null;
        }
        Input in = inputs.get(index);
        byte[] prevTxHash = in.prevTxHash;
        ByteBuffer byteBuffer = ByteBuffer.allocate(Integer.SIZE / 8);
        byteBuffer.putInt(in.outputIndex);
        byte[] outputIndex = byteBuffer.array();

        List<Byte> sigData = new ArrayList<>();
        if (prevTxHash != null) {
            for (int i = 0; i < prevTxHash.length; i++) {
                sigData.add(prevTxHash[i]);
            }
        }
        for (int i = 0; i < outputIndex.length; i++) {
            sigData.add(outputIndex[i]);
        }
        for (Output op : outputs) {
            ByteBuffer bo = ByteBuffer.allocate(Double.SIZE / 8);
            bo.putDouble(op.value);
            byte[] value = bo.array();
            byte[] addressBytes = op.address.getEncoded();
            for (int i = 0; i < value.length; i++) {
                sigData.add(value[i]);
            }

            for (int i = 0; i < addressBytes.length; i++) {
                sigData.add(addressBytes[i]);
            }
        }
        byte[] sigD = new byte[sigData.size()];
        int idx = 0;
        for (Byte sb : sigData) {
            sigD[idx++] = sb;
        }
        return sigD;
    }

    public void addSignature(byte[] signature, int index) {
        inputs.get(index).addSignature(signature);
    }

    @SuppressWarnings("PMD.CyclomaticComplexity")
    public byte[] getRawTx() {
        ArrayList<Byte> rawTx = new ArrayList<Byte>();
        for (Input in : inputs) {
            byte[] prevTxHash = in.prevTxHash;
            ByteBuffer byteBuffer = ByteBuffer.allocate(Integer.SIZE / 8);
            byteBuffer.putInt(in.outputIndex);
            byte[] outputIndex = byteBuffer.array();
            byte[] signature = in.signature;
            if (prevTxHash != null) {
                for (int i = 0; i < prevTxHash.length; i++) {
                    rawTx.add(prevTxHash[i]);
                }
            }

            for (int i = 0; i < outputIndex.length; i++) {
                rawTx.add(outputIndex[i]);
            }
            if (signature != null) {
                for (int i = 0; i < signature.length; i++) {
                    rawTx.add(signature[i]);
                }
            }
        }
        for (Output op : outputs) {
            ByteBuffer byteBuffer = ByteBuffer.allocate(Double.SIZE / 8);
            byteBuffer.putDouble(op.value);
            byte[] value = byteBuffer.array();
            byte[] addressBytes = op.address.getEncoded();
            for (int i = 0; i < value.length; i++) {
                rawTx.add(value[i]);
            }
            for (int i = 0; i < addressBytes.length; i++) {
                rawTx.add(addressBytes[i]);
            }

        }
        byte[] tx = new byte[rawTx.size()];
        int idx = 0;
        for (Byte bb : rawTx) {
            tx[idx++] = bb;
        }
        return tx;
    }

    public void calculateHash() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(getRawTx());
            hash = md.digest();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace(System.err);
        }
    }

    @SuppressWarnings("PMD.ArrayIsStoredDirectly")
    public void setHash(byte[] hash) {
        this.hash = hash;
    }

    @SuppressWarnings("PMD.MethodReturnsInternalArray")
    public byte[] getHash() {
        return hash;
    }

    public List<Input> getInputs() {
        return inputs;
    }

    public List<Output> getOutputs() {
        return outputs;
    }

    public Input getInput(int index) {
        if (index < inputs.size()) {
            return inputs.get(index);
        }
        return null;
    }

    public Output getOutput(int index) {
        if (index < outputs.size()) {
            return outputs.get(index);
        }
        return null;
    }

    public int numInputs() {
        return inputs.size();
    }

    public int numOutputs() {
        return outputs.size();
    }

}
