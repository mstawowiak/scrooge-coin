package com.github.mstawowiak.blockchain.scroogecoin

import com.github.mstawowiak.blockchain.scroogecoin.crypto.Crypto
import com.github.mstawowiak.blockchain.scroogecoin.crypto.HashCalculcator
import com.github.mstawowiak.blockchain.scroogecoin.crypto.RSA
import org.apache.commons.lang3.tuple.Pair
import spock.lang.Specification

import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

import static org.junit.Assert.assertEquals

class TxHandlerGroovyTest extends Specification {

    TxHandler txHandler
    UTXOPool utxoPool
    List<Transaction> transactions

    static final byte[] TX_A_HASH = HashCalculcator.calculateSHA256("GENESIS_BLOCK_A")

    static final int TX_A0_INDEX = 0
    static final UTXO UTXO_A0 = UTXO.of(TX_A_HASH, TX_A0_INDEX)
    static final double UTXO_A0_VALUE = 80

    static final int TX_A1_INDEX = 1
    static final UTXO UTXO_A1 = UTXO.of(TX_A_HASH, TX_A1_INDEX)
    static final double UTXO_A1_VALUE = 20

    static final byte[] TX_B_HASH = HashCalculcator.calculateSHA256("GENESIS_BLOCK_B")

    static final int TX_B0_INDEX = 0
    static final UTXO UTXO_B0 = UTXO.of(TX_B_HASH, TX_B0_INDEX)
    static final double UTXO_B0_VALUE = 200

    static final int TX_B1_INDEX = 1
    static final UTXO UTXO_B1 = UTXO.of(TX_B_HASH, TX_B1_INDEX)
    static final double UTXO_B1_VALUE = 100

    static final double NEGATIVE_VALUE = -100.0

    static final KeyPair JOHN_KEY_PAIR = RSA.generateRSA2048()
    static final PublicKey JOHN_PUBLIC_KEY = JOHN_KEY_PAIR.getPublic()

    static final KeyPair MARK_KEY_PAIR = RSA.generateRSA2048()
    static final PublicKey MARK_PUBLIC_KEY = MARK_KEY_PAIR.getPublic()

    static final KeyPair SAM_KEY_PAIR = RSA.generateRSA2048()
    static final PublicKey SAM_PUBLIC_KEY = SAM_KEY_PAIR.getPublic()

    def setup() {
        initUTXOPool()
        txHandler = new TxHandler(utxoPool)
        transactions = new ArrayList<>()
    }

    private void initUTXOPool() {
        utxoPool = new UTXOPool()

        utxoPool.addUTXO(UTXO_A0, new Transaction.Output(new Transaction(), UTXO_A0_VALUE, JOHN_PUBLIC_KEY))
        utxoPool.addUTXO(UTXO_A1, new Transaction.Output(new Transaction(), UTXO_A1_VALUE, JOHN_PUBLIC_KEY))

        utxoPool.addUTXO(UTXO_B0, new Transaction.Output(new Transaction(), UTXO_B0_VALUE, JOHN_PUBLIC_KEY))
        utxoPool.addUTXO(UTXO_B1, new Transaction.Output(new Transaction(), UTXO_B1_VALUE, JOHN_PUBLIC_KEY))
    }

    def "should return empty list for empty input transactions"() {
        given: 'empty transaction list'
        List<Transaction> emptyTransactionList = Collections.emptyList()

        expect:
        txHandler.handleTxs(emptyTransactionList).size() == 0
    }

    def "should handle one transaction"() {
        given: 'one valid transaction'
        List<UTXO> inputs = Collections.singletonList(UTXO_A0)

        List<Pair<Double, PublicKey>> outputs = new ArrayList<>()
        outputs.add(Pair.of(UTXO_A0_VALUE, MARK_PUBLIC_KEY))

        transactions.add(makeTxn(JOHN_KEY_PAIR.getPrivate(), inputs, outputs))

        expect:
        txHandler.handleTxs(transactions).size() == 1
    }

    def "should handle one transaction with few outputs"() {
        given: 'transaction with 3 outputs'
        List<UTXO> inputs = Collections.singletonList(UTXO_B0)

        List<Pair<Double, PublicKey>> outputs = new ArrayList<>()
        outputs.add(Pair.of(80.0, MARK_PUBLIC_KEY))
        outputs.add(Pair.of(50.0, MARK_PUBLIC_KEY))
        outputs.add(Pair.of(70.0, MARK_PUBLIC_KEY))

        transactions.add(makeTxn(JOHN_KEY_PAIR.getPrivate(), inputs, outputs))

        expect:
        txHandler.handleTxs(transactions).size() == 1
    }

    def "should handle one transaction with few inputs"() {
        given: 'transaction with 2 inputs'
        List<UTXO> inputs = new ArrayList<>()
        inputs.add(UTXO_A0)
        inputs.add(UTXO_A1)

        List<Pair<Double, PublicKey>> outputs = new ArrayList<>()
        outputs.add(Pair.of(UTXO_A0_VALUE + UTXO_A1_VALUE, MARK_PUBLIC_KEY))

        transactions.add(makeTxn(JOHN_KEY_PAIR.getPrivate(), inputs, outputs))

        expect:
        txHandler.handleTxs(transactions).size() == 1
    }

    def "should handle few transactions"() {
        given: '4 valid transactions'
        transactions.add(
                makeTxn(JOHN_KEY_PAIR.getPrivate(),
                        Collections.singletonList(UTXO_A0),
                        Collections.singletonList(Pair.of(UTXO_A0_VALUE, MARK_PUBLIC_KEY))))
        transactions.add(
                makeTxn(JOHN_KEY_PAIR.getPrivate(),
                        Collections.singletonList(UTXO_A1),
                        Collections.singletonList(Pair.of(UTXO_A1_VALUE, MARK_PUBLIC_KEY))))
        transactions.add(
                makeTxn(JOHN_KEY_PAIR.getPrivate(),
                        Collections.singletonList(UTXO_B0),
                        Collections.singletonList(Pair.of(UTXO_B0_VALUE, MARK_PUBLIC_KEY))))
        transactions.add(
                makeTxn(JOHN_KEY_PAIR.getPrivate(),
                        Collections.singletonList(UTXO_B1),
                        Collections.singletonList(Pair.of(UTXO_B1_VALUE, MARK_PUBLIC_KEY))))

        expect:
        txHandler.handleTxs(transactions).size() == 4
    }

    def "should reject invalid transations"() {
        given: 'valid transaction'
        transactions.add(
                makeTxn(JOHN_KEY_PAIR.getPrivate(),
                        Collections.singletonList(UTXO_A0),
                        Collections.singletonList(Pair.of(UTXO_A0_VALUE, MARK_PUBLIC_KEY))))
        and: '3 invalid transactions: '
        'double spend'
        transactions.add(
                makeTxn(JOHN_KEY_PAIR.getPrivate(),
                        Collections.singletonList(UTXO_A0),
                        Collections.singletonList(Pair.of(UTXO_A0_VALUE, MARK_PUBLIC_KEY))))
        'negative output'
        transactions.add(
                makeTxn(JOHN_KEY_PAIR.getPrivate(),
                        Collections.singletonList(UTXO_A1),
                        Collections.singletonList(Pair.of(NEGATIVE_VALUE, MARK_PUBLIC_KEY))))
        'outputs > inputs'
        transactions.add(
                makeTxn(JOHN_KEY_PAIR.getPrivate(),
                        Collections.singletonList(UTXO_B0),
                        Collections.singletonList(Pair.of(UTXO_B0_VALUE + 1, MARK_PUBLIC_KEY))))

        expect:
        txHandler.handleTxs(transactions).size() == 1
    }

    def "should handle two blocks in a row"() {
        given:

        Transaction transactionJohnToMark = makeTxn(JOHN_KEY_PAIR.getPrivate(),
                Collections.singletonList(UTXO_A0),
                Collections.singletonList(Pair.of(UTXO_A0_VALUE, MARK_PUBLIC_KEY)))

        when:
        List<Transaction> result1 = txHandler.handleTxs(Collections.singletonList(transactionJohnToMark));

        then:
        assertEquals(1, result1.size())

        and: 'Create next transaction based on transactionJohnToMark'
        Transaction transactionMarkToSam = makeTxn(MARK_KEY_PAIR.getPrivate(),
                Collections.singletonList(UTXO.of(transactionJohnToMark.getHash(), 0)),
                Collections.singletonList(Pair.of(UTXO_A0_VALUE, SAM_PUBLIC_KEY)))

        when:
        List<Transaction> result2 = txHandler.handleTxs(Collections.singletonList(transactionMarkToSam));

        then:
        assertEquals(1, result2.size())
    }

    private Transaction makeTxn(PrivateKey privateKey, List<UTXO> utxos, List<Pair<Double, PublicKey>> outputs) {
        Transaction transaction = new Transaction()
        for (Pair<Double, PublicKey> output : outputs) {
            transaction.addOutput(output.getLeft(), output.getRight())
        }

        int inputIdx = 0
        for (UTXO utxo : utxos) {
            transaction.addInput(utxo.getTxHash(), utxo.getIndex())

            byte[] signature = Crypto.sign(privateKey, transaction.getRawDataToSign(inputIdx))
            transaction.addSignature(signature, inputIdx)
            inputIdx++
        }

        transaction.calculateHash()

        return transaction
    }

}
