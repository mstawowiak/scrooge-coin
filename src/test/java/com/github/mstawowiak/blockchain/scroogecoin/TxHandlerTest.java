package com.github.mstawowiak.blockchain.scroogecoin;

import com.github.mstawowiak.blockchain.scroogecoin.crypto.Crypto;
import com.github.mstawowiak.blockchain.scroogecoin.crypto.HashCalculcator;
import com.github.mstawowiak.blockchain.scroogecoin.crypto.RSA;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Tests for {@link TxHandler}
 */
public class TxHandlerTest {

    private TxHandler txHandler;
    private UTXOPool utxoPool;
    private List<Transaction> transactions;

    private static final byte[] TX_A_HASH = HashCalculcator.calculateSHA256("GENESIS_BLOCK_A");

    private static final int TX_A0_INDEX = 0;
    private static final UTXO UTXO_A0 = UTXO.of(TX_A_HASH, TX_A0_INDEX);
    private static final double UTXO_A0_VALUE = 80;

    private static final int TX_A1_INDEX = 1;
    private static final UTXO UTXO_A1 = UTXO.of(TX_A_HASH, TX_A1_INDEX);
    private static final double UTXO_A1_VALUE = 20;

    private static final byte[] TX_B_HASH = HashCalculcator.calculateSHA256("GENESIS_BLOCK_B");

    private static final int TX_B0_INDEX = 0;
    private static final UTXO UTXO_B0 = UTXO.of(TX_B_HASH, TX_B0_INDEX);
    private static final double UTXO_B0_VALUE = 200;

    private static final int TX_B1_INDEX = 1;
    private static final UTXO UTXO_B1 = UTXO.of(TX_B_HASH, TX_B1_INDEX);
    private static final double UTXO_B1_VALUE = 100;

    private static final KeyPair JOHN_KEY_PAIR = RSA.generateRSA2048();
    private static final PublicKey JOHN_PUBLIC_KEY = JOHN_KEY_PAIR.getPublic();

    private static final KeyPair MARK_KEY_PAIR = RSA.generateRSA2048();
    private static final PublicKey MARK_PUBLIC_KEY = MARK_KEY_PAIR.getPublic();

    @Before
    public void beforeTest() {
        initUTXOPool();
        txHandler = new TxHandler(utxoPool);
        transactions = new ArrayList<>();
    }

    private void initUTXOPool() {
        utxoPool = new UTXOPool();

        utxoPool.addUTXO(UTXO_A0, new Transaction().new Output(UTXO_A0_VALUE, JOHN_PUBLIC_KEY));
        utxoPool.addUTXO(UTXO_A1, new Transaction().new Output(UTXO_A1_VALUE, JOHN_PUBLIC_KEY));

        utxoPool.addUTXO(UTXO_B0, new Transaction().new Output(UTXO_B0_VALUE, JOHN_PUBLIC_KEY));
        utxoPool.addUTXO(UTXO_B1, new Transaction().new Output(UTXO_B1_VALUE, JOHN_PUBLIC_KEY));
    }

    @Test
    public void shouldReturnEmptyListForEmptyInput() {
        List<Transaction> result = txHandler.handleTxs(transactions);

        assertEquals(0, result.size());
    }

    @Test
    public void shouldHandleOneTransaction() {
        List<UTXO> inputs = Collections.singletonList(UTXO_A0);

        List<Pair<Double, PublicKey>> outputs = new ArrayList<>();
        outputs.add(Pair.of(UTXO_A0_VALUE, MARK_PUBLIC_KEY));

        transactions.add(makeTxn(JOHN_KEY_PAIR.getPrivate(), inputs, outputs));

        //when
        List<Transaction> result = txHandler.handleTxs(transactions);

        assertEquals(1, result.size());
    }

    @Test
    public void shouldHandleOneTransactionWithFewOutputs() {
        List<UTXO> inputs = Collections.singletonList(UTXO_B0);

        List<Pair<Double, PublicKey>> outputs = new ArrayList<>();
        outputs.add(Pair.of(new Double(80), MARK_PUBLIC_KEY));
        outputs.add(Pair.of(new Double(50), MARK_PUBLIC_KEY));
        outputs.add(Pair.of(new Double(70), MARK_PUBLIC_KEY));

        transactions.add(makeTxn(JOHN_KEY_PAIR.getPrivate(), inputs, outputs));

        //when
        List<Transaction> result = txHandler.handleTxs(transactions);

        assertEquals(1, result.size());
    }

    @Test
    public void shouldHandleOneTransactionWithFewInputs() {
        List<UTXO> inputs = new ArrayList<>();
        inputs.add(UTXO_A0);
        inputs.add(UTXO_A1);

        List<Pair<Double, PublicKey>> outputs = new ArrayList<>();
        outputs.add(Pair.of(UTXO_A0_VALUE + UTXO_A1_VALUE, MARK_PUBLIC_KEY));

        transactions.add(makeTxn(JOHN_KEY_PAIR.getPrivate(), inputs, outputs));

        //when
        List<Transaction> result = txHandler.handleTxs(transactions);

        assertEquals(1, result.size());
    }

    private Transaction makeTxn(PrivateKey privateKey, List<UTXO> utxos, List<Pair<Double, PublicKey>> outputs) {
        Transaction transaction = new Transaction();
        for (Pair<Double, PublicKey> output : outputs) {
            transaction.addOutput(output.getLeft(), output.getRight());
        }

        int inputIdx = 0;
        for (UTXO utxo: utxos) {
            transaction.addInput(utxo.getTxHash(), utxo.getIndex());

            byte[] signature = Crypto.sign(privateKey, transaction.getRawDataToSign(inputIdx));
            transaction.addSignature(signature, inputIdx);
            inputIdx++;
        }

        transaction.calculateHash();

        return transaction;
    }

}
