package com.github.mstawowiak.blockchain.scroogecoin;

import com.github.mstawowiak.blockchain.scroogecoin.crypto.Crypto;
import com.github.mstawowiak.blockchain.scroogecoin.crypto.HashCalculcator;
import com.github.mstawowiak.blockchain.scroogecoin.crypto.RSA;
import java.security.KeyPair;
import java.security.PublicKey;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Tests for {@link TxValidator}
 */
public class TxValidatorTest {

    private UTXOPool utxoPool;
    private Transaction tx;

    private static final byte[] TX_A_HASH = HashCalculcator.calculateSHA256("GENESIS_BLOCK_A");
    private static final int TX_A_INDEX = 0;
    private static final UTXO UTXO_A = UTXO.of(TX_A_HASH, TX_A_INDEX);

    private static final byte[] TX_B_HASH = HashCalculcator.calculateSHA256("GENESIS_BLOCK_B");
    private static final int TX_B_INDEX = 0;
    private static final UTXO UTXO_B = UTXO.of(TX_B_HASH, TX_B_INDEX);

    private static final double ZERO_VALUE = 0;
    private static final double POSITIVE_VALUE = 100.0;
    private static final double NEGATIVE_VALUE = -100.0;

    private static final KeyPair JOHN_KEY_PAIR = RSA.generateRSA2048();
    private static final PublicKey JOHN_PUBLIC_KEY = JOHN_KEY_PAIR.getPublic();
    private static final Transaction.Output JOHN_OUTPUT = new Transaction().new Output(POSITIVE_VALUE, JOHN_PUBLIC_KEY);

    private static final KeyPair MARK_KEY_PAIR = RSA.generateRSA2048();
    private static final PublicKey MARK_PUBLIC_KEY = MARK_KEY_PAIR.getPublic();

    @Before
    public void beforeTest() {
        utxoPool = new UTXOPool();
        tx = new Transaction();
    }

    @Test
    public void shouldAllOutputsExistsInPoolForSingleInput() {
        utxoPool.addUTXO(UTXO_A, JOHN_OUTPUT);
        tx.addInput(TX_A_HASH, TX_A_INDEX);

        boolean result = TxValidator.allOutputsExistsInPool(tx, utxoPool);

        assertTrue(result);
    }

    @Test
    public void shouldAllOutputsExistsInPoolForTwoInputs() {
        utxoPool.addUTXO(UTXO_A, JOHN_OUTPUT);
        utxoPool.addUTXO(UTXO_B, JOHN_OUTPUT);
        tx.addInput(TX_A_HASH, TX_A_INDEX);
        tx.addInput(TX_B_HASH, TX_B_INDEX);

        boolean result = TxValidator.allOutputsExistsInPool(tx, utxoPool);

        assertTrue(result);
    }

    @Test
    public void shouldReturnFalseForMissingOutput() {
        utxoPool.addUTXO(UTXO_A, JOHN_OUTPUT);
        tx.addInput(TX_A_HASH, TX_A_INDEX);
        tx.addInput(TX_B_HASH, TX_B_INDEX);

        boolean result = TxValidator.allOutputsExistsInPool(tx, utxoPool);

        assertFalse(result);
    }

    @Test
    public void shouldReturnTrueForValidSignatures() {
        utxoPool.addUTXO(UTXO_A, JOHN_OUTPUT);
        utxoPool.addUTXO(UTXO_B, JOHN_OUTPUT);
        tx.addInput(TX_A_HASH, TX_A_INDEX);
        tx.addInput(TX_B_HASH, TX_B_INDEX);
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY);
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY);
        tx.addSignature(Crypto.sign(JOHN_KEY_PAIR.getPrivate(), tx.getRawDataToSign(0)), 0);
        tx.addSignature(Crypto.sign(JOHN_KEY_PAIR.getPrivate(), tx.getRawDataToSign(1)), 1);

        boolean result = TxValidator.allInputsSignaturesAreValid(tx, utxoPool);

        assertTrue(result);
    }

    @Test
    public void shouldReturnFalseForWrongSignature() {
        utxoPool.addUTXO(UTXO_A, JOHN_OUTPUT);
        tx.addInput(TX_A_HASH, TX_A_INDEX);
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY);
        tx.addSignature(Crypto.sign(MARK_KEY_PAIR.getPrivate(), tx.getRawDataToSign(0)), 0);

        boolean result = TxValidator.allInputsSignaturesAreValid(tx, utxoPool);

        assertFalse(result);
    }

    @Test
    public void shouldReturnTrueForNoDoubleSpend() {
        tx.addInput(TX_A_HASH, TX_A_INDEX);
        tx.addInput(TX_B_HASH, TX_B_INDEX);

        boolean result = TxValidator.noDoubleSpend(tx);

        assertTrue(result);
    }

    @Test
    public void shouldReturnFalseForDoubleSpend() {
        tx.addInput(TX_A_HASH, TX_A_INDEX);
        tx.addInput(TX_A_HASH, TX_A_INDEX);

        boolean result = TxValidator.noDoubleSpend(tx);

        assertFalse(result);
    }

    @Test
    public void shouldReturnTrueForPositiveOutputs() {
        tx.addOutput(POSITIVE_VALUE, JOHN_PUBLIC_KEY);
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY);

        boolean result = TxValidator.allOutputsAreNonNegative(tx);

        assertTrue(result);
    }

    @Test
    public void shouldReturnTrueForZeroValueOutput() {
        tx.addOutput(ZERO_VALUE, JOHN_PUBLIC_KEY);

        boolean result = TxValidator.allOutputsAreNonNegative(tx);

        assertTrue(result);
    }

    @Test
    public void shouldReturnFalseForNegativeOutput() {
        tx.addOutput(NEGATIVE_VALUE, JOHN_PUBLIC_KEY);

        boolean result = TxValidator.allOutputsAreNonNegative(tx);

        assertFalse(result);
    }

    @Test
    public void shouldReturnTrueIfInputsGreaterThanOutputs() {
        utxoPool.addUTXO(UTXO_A, JOHN_OUTPUT);
        utxoPool.addUTXO(UTXO_B, new Transaction().new Output(POSITIVE_VALUE + 1, JOHN_PUBLIC_KEY));
        tx.addInput(TX_A_HASH, TX_A_INDEX);
        tx.addInput(TX_B_HASH, TX_B_INDEX);
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY);
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY);

        boolean result = TxValidator.sumInputsGeOutputs(tx, utxoPool);

        assertTrue(result);
    }

    @Test
    public void shouldReturnTrueIfInputsEqualOutputs() {
        utxoPool.addUTXO(UTXO_A, JOHN_OUTPUT);
        utxoPool.addUTXO(UTXO_B, JOHN_OUTPUT);
        tx.addInput(TX_A_HASH, TX_A_INDEX);
        tx.addInput(TX_B_HASH, TX_B_INDEX);
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY);
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY);

        boolean result = TxValidator.sumInputsGeOutputs(tx, utxoPool);

        assertTrue(result);
    }

    @Test
    public void shouldReturnTrueIfInputsLowerThanOutputs() {
        utxoPool.addUTXO(UTXO_A, JOHN_OUTPUT);
        tx.addInput(TX_A_HASH, TX_A_INDEX);
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY);
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY);

        boolean result = TxValidator.sumInputsGeOutputs(tx, utxoPool);

        assertFalse(result);
    }

}
