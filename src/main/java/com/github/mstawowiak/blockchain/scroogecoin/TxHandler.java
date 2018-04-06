package com.github.mstawowiak.blockchain.scroogecoin;

import java.util.ArrayList;
import java.util.List;

public class TxHandler {

    private final UTXOPool currentUtxoPool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        this.currentUtxoPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid,
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     * values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        return TxValidator.allOutputsExistsInPool(tx, currentUtxoPool)
                && TxValidator.allInputsSignaturesAreValid(tx, currentUtxoPool)
                && TxValidator.noDoubleSpend(tx)
                && TxValidator.allOutputsAreNonNegative(tx)
                && TxValidator.sumInputsGeOutputs(tx, currentUtxoPool);
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public List<Transaction> handleTxs(List<Transaction> possibleTxs) {
        List<Transaction> choosenTxs = new ArrayList<>();

        for (Transaction tx : possibleTxs) {
            if (!isValidTx(tx)) {
                continue;
            }

            choosenTxs.add(tx);

            removeInputsFromPool(tx);
            addOutputsToPool(tx);
        }

        return choosenTxs;
    }

    private void removeInputsFromPool(Transaction tx) {
        for (Transaction.Input input : tx.getInputs()) {
            currentUtxoPool.removeUTXO(UTXO.of(input.prevTxHash, input.outputIndex));
        }
    }

    private void addOutputsToPool(Transaction tx) {
        for (int i = 0; i < tx.getOutputs().size(); i++) {
            UTXO utxo = UTXO.of(tx.getHash(), i);
            Transaction.Output output = tx.getOutput(i);

            currentUtxoPool.addUTXO(utxo, output);
        }
    }
}
