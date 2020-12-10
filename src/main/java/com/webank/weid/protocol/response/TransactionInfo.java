/*
 *       Copyright© (2019) WeBank Co., Ltd.
 *
 *       This file is part of weid-java-sdk.
 *
 *       weid-java-sdk is free software: you can redistribute it and/or modify
 *       it under the terms of the GNU Lesser General Public License as published by
 *       the Free Software Foundation, either version 3 of the License, or
 *       (at your option) any later version.
 *
 *       weid-java-sdk is distributed in the hope that it will be useful,
 *       but WITHOUT ANY WARRANTY; without even the implied warranty of
 *       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *       GNU Lesser General Public License for more details.
 *
 *       You should have received a copy of the GNU Lesser General Public License
 *       along with weid-java-sdk.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.webank.weid.protocol.response;

import java.math.BigInteger;

import lombok.Data;

import org.fisco.bcos.sdk.model.TransactionReceipt;
import org.fisco.bcos.sdk.utils.Numeric;

/**
 * The basic transaction information. Caller can further use these information to track the detailed
 * transaction instance from blockchain.
 *
 * @author chaoxinhu 2019.4
 */

@Data
public class TransactionInfo {

    /**
     * The block number.
     */
    private BigInteger blockNumber;

    /**
     * The transaction hash value.
     */
    private String transactionHash;

    /**
     * The transaction index.
     */
    private BigInteger transactionIndex;

    /**
     * Constructor from a transactionReceipt.
     *
     * @param receipt the transaction receipt
     */
    public TransactionInfo(TransactionReceipt receipt) {
        if (receipt != null) {
            this.blockNumber = new BigInteger(Numeric.cleanHexPrefix(receipt.getBlockNumber()), 16);
            this.transactionHash = receipt.getTransactionHash();
            this.transactionIndex = new BigInteger(
                Numeric.cleanHexPrefix(receipt.getTransactionIndex()), 16);
        }
    }

    /**
     * Constructor.
     *
     * @param blockNumber blockNumber
     * @param transactionHash transactionHash
     * @param transactionIndex transactionIndex
     */
    public TransactionInfo(BigInteger blockNumber,
        String transactionHash,
        BigInteger transactionIndex) {
        this.blockNumber = blockNumber;
        this.transactionHash = transactionHash;
        this.transactionIndex = transactionIndex;
    }
}
