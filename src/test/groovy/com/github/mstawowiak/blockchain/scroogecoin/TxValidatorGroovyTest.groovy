package com.github.mstawowiak.blockchain.scroogecoin

import com.github.mstawowiak.blockchain.scroogecoin.crypto.Crypto
import com.github.mstawowiak.blockchain.scroogecoin.crypto.HashCalculcator
import com.github.mstawowiak.blockchain.scroogecoin.crypto.RSA
import spock.lang.Specification

import java.security.KeyPair
import java.security.PublicKey

class TxValidatorGroovyTest extends Specification {

    UTXOPool utxoPool
    Transaction tx

    static final byte[] TX_A_HASH = HashCalculcator.calculateSHA256("GENESIS_BLOCK_A")
    static final int TX_A_INDEX = 0
    static final UTXO UTXO_A = UTXO.of(TX_A_HASH, TX_A_INDEX)

    static final byte[] TX_B_HASH = HashCalculcator.calculateSHA256("GENESIS_BLOCK_B")
    static final int TX_B_INDEX = 0
    static final UTXO UTXO_B = UTXO.of(TX_B_HASH, TX_B_INDEX)

    static final double ZERO_VALUE = 0
    static final double POSITIVE_VALUE = 100.0
    static final double NEGATIVE_VALUE = -100.0

    static final KeyPair JOHN_KEY_PAIR = RSA.generateRSA2048()
    static final PublicKey JOHN_PUBLIC_KEY = JOHN_KEY_PAIR.getPublic()

    static final Transaction.Output JOHN_OUTPUT = new Transaction.Output(new Transaction(), POSITIVE_VALUE, JOHN_PUBLIC_KEY)

    static final KeyPair MARK_KEY_PAIR = RSA.generateRSA2048()
    static final PublicKey MARK_PUBLIC_KEY = MARK_KEY_PAIR.getPublic()

    def setup() {
        utxoPool = new UTXOPool()
        tx = new Transaction()
    }

    def "should return true if all outputs exists in pool for single input"() {
        given:
        utxoPool.addUTXO(UTXO_A, JOHN_OUTPUT)
        tx.addInput(TX_A_HASH, TX_A_INDEX)

        expect:
        TxValidator.allOutputsExistsInPool(tx, utxoPool) == true
    }

    def "should return true if all outputs exists in pool for two inputs"() {
        given:
        utxoPool.addUTXO(UTXO_A, JOHN_OUTPUT)
        utxoPool.addUTXO(UTXO_B, JOHN_OUTPUT)
        tx.addInput(TX_A_HASH, TX_A_INDEX)
        tx.addInput(TX_B_HASH, TX_B_INDEX)

        expect:
        TxValidator.allOutputsExistsInPool(tx, utxoPool) == true
    }

    def "should return false for missing output in UTXO pool"() {
        given:
        utxoPool.addUTXO(UTXO_A, JOHN_OUTPUT)
        tx.addInput(TX_A_HASH, TX_A_INDEX)
        tx.addInput(TX_B_HASH, TX_B_INDEX)

        expect:
        TxValidator.allOutputsExistsInPool(tx, utxoPool) == false
    }

    def "should return true for valid signatures"() {
        given:
        utxoPool.addUTXO(UTXO_A, JOHN_OUTPUT)
        utxoPool.addUTXO(UTXO_B, JOHN_OUTPUT)
        tx.addInput(TX_A_HASH, TX_A_INDEX)
        tx.addInput(TX_B_HASH, TX_B_INDEX)
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY)
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY)
        tx.addSignature(Crypto.sign(JOHN_KEY_PAIR.getPrivate(), tx.getRawDataToSign(0)), 0)
        tx.addSignature(Crypto.sign(JOHN_KEY_PAIR.getPrivate(), tx.getRawDataToSign(1)), 1)

        expect:
        TxValidator.allInputsSignaturesAreValid(tx, utxoPool) == true
    }

    def "should return false for wrong signature"() {
        given:
        utxoPool.addUTXO(UTXO_A, JOHN_OUTPUT)
        tx.addInput(TX_A_HASH, TX_A_INDEX)
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY)
        tx.addSignature(Crypto.sign(MARK_KEY_PAIR.getPrivate(), tx.getRawDataToSign(0)), 0)

        expect:
        TxValidator.allInputsSignaturesAreValid(tx, utxoPool) == false
    }

    def "should return true for no double spend"() {
        given:
        tx.addInput(TX_A_HASH, TX_A_INDEX)
        tx.addInput(TX_B_HASH, TX_B_INDEX)

        expect:
        TxValidator.noDoubleSpend(tx) == true
    }

    def "should return false for double spend"() {
        given:
        tx.addInput(TX_A_HASH, TX_A_INDEX)
        tx.addInput(TX_A_HASH, TX_A_INDEX)

        expect:
        TxValidator.noDoubleSpend(tx) == false
    }

    def "should return true for positive outputs"() {
        given:
        tx.addOutput(POSITIVE_VALUE, JOHN_PUBLIC_KEY)
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY)

        expect:
        TxValidator.allOutputsAreNonNegative(tx) == true
    }

    def "should return true for 0 value output"() {
        given:
        tx.addOutput(ZERO_VALUE, JOHN_PUBLIC_KEY)

        expect:
        TxValidator.allOutputsAreNonNegative(tx) == true
    }

    def "should return false for negative output"() {
        given:
        tx.addOutput(NEGATIVE_VALUE, JOHN_PUBLIC_KEY)

        expect:
        TxValidator.allOutputsAreNonNegative(tx) == false
    }

    def "should return true if inputs are greater than outputs"() {
        given:
        utxoPool.addUTXO(UTXO_A, JOHN_OUTPUT)
        utxoPool.addUTXO(UTXO_B, new Transaction.Output(new Transaction(), POSITIVE_VALUE + 1, JOHN_PUBLIC_KEY))
        tx.addInput(TX_A_HASH, TX_A_INDEX)
        tx.addInput(TX_B_HASH, TX_B_INDEX)
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY)
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY)

        expect:
        TxValidator.sumInputsGeOutputs(tx, utxoPool) == true
    }

    def "should return true if inputs are equal outputs"() {
        given:
        utxoPool.addUTXO(UTXO_A, JOHN_OUTPUT)
        utxoPool.addUTXO(UTXO_B, JOHN_OUTPUT)
        tx.addInput(TX_A_HASH, TX_A_INDEX)
        tx.addInput(TX_B_HASH, TX_B_INDEX)
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY)
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY)

        expect:
        TxValidator.sumInputsGeOutputs(tx, utxoPool) == true
    }

    def "should return false if inputs are lower than outputs"() {
        given:
        utxoPool.addUTXO(UTXO_A, JOHN_OUTPUT)
        tx.addInput(TX_A_HASH, TX_A_INDEX)
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY)
        tx.addOutput(POSITIVE_VALUE, MARK_PUBLIC_KEY)

        expect:
        TxValidator.sumInputsGeOutputs(tx, utxoPool) == false
    }

}
