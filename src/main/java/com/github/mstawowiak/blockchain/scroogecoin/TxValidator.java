package com.github.mstawowiak.blockchain.scroogecoin;

import com.github.mstawowiak.blockchain.scroogecoin.crypto.Crypto;
import java.util.HashSet;
import java.util.stream.IntStream;

public final class TxValidator {

    public static boolean allOutputsExistsInPool(final Transaction tx, final UTXOPool utxoPool) {
        return tx.getInputs().stream()
                .allMatch(input -> utxoPool.contains(UTXO.of(input.prevTxHash, input.outputIndex)));
    }

    public static boolean allInputsSignaturesAreValid(final Transaction tx, final UTXOPool utxoPool) {
        return IntStream.range(0, tx.getInputs().size()).allMatch(index -> {
            Transaction.Input input = tx.getInput(index);
            UTXO utxo = UTXO.of(input.prevTxHash, input.outputIndex);
            Transaction.Output output = utxoPool.getTxOutput(utxo);

            return Crypto.verifySignature(output.address, tx.getRawDataToSign(index), input.signature);
        });
    }

    public static boolean noDoubleSpend(final Transaction tx) {
        return tx.getInputs().stream()
                .map(input -> UTXO.of(input.prevTxHash, input.outputIndex))
                .allMatch(new HashSet<>()::add);
    }

    public static boolean allOutputsAreNonNegative(final Transaction tx) {
        return tx.getOutputs().stream()
                .allMatch(output -> output.value >= 0);
    }

    public static boolean sumInputsGeOutputs(final Transaction tx, final UTXOPool utxoPool) {
        double inputSum = tx.getInputs().stream()
                .map(input -> UTXO.of(input.prevTxHash, input.outputIndex))
                .map(utxo -> utxoPool.getTxOutput(utxo))
                .map(output -> output.value)
                .reduce(Double::sum)
                .get();

        double outputSum = tx.getOutputs().stream()
                .map(output -> output.value)
                .reduce(Double::sum)
                .get();

        return inputSum >= outputSum;
    }

    private TxValidator() {
    }
}
