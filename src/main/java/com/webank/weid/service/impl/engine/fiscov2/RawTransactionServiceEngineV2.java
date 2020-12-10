/*
 *       Copyright© (2018-2019) WeBank Co., Ltd.
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

package com.webank.weid.service.impl.engine.fiscov2;

import java.util.List;
import java.util.Optional;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.client.protocol.response.BcosTransactionReceipt;
import org.fisco.bcos.sdk.client.protocol.response.SendTransaction;
import org.fisco.bcos.sdk.model.TransactionReceipt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.contract.v2.AuthorityIssuerController;
import com.webank.weid.contract.v2.AuthorityIssuerController.AuthorityIssuerRetLogEventResponse;
import com.webank.weid.contract.v2.CptController;
import com.webank.weid.contract.v2.CptController.RegisterCptRetLogEventResponse;
import com.webank.weid.contract.v2.WeIdContract;
import com.webank.weid.contract.v2.WeIdContract.WeIdAttributeChangedEventResponse;
import com.webank.weid.exception.WeIdBaseException;
import com.webank.weid.protocol.base.CptBaseInfo;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.protocol.response.TransactionInfo;
import com.webank.weid.service.impl.engine.BaseEngine;
import com.webank.weid.service.impl.engine.RawTransactionServiceEngine;
import com.webank.weid.util.DataToolUtils;
import com.webank.weid.util.TransactionUtils;

/**
 * RawTransactionService runs on FISCO BCOS 2.0.
 *
 * @author tonychen 2019年6月26日
 */
public class RawTransactionServiceEngineV2 extends BaseEngine implements
    RawTransactionServiceEngine {

    private static final Logger logger = LoggerFactory
        .getLogger(RawTransactionServiceEngineV2.class);

    /**
     * WeIdentity DID contract object, for calling weIdentity DID contract.
     */
    private static WeIdContract weIdContract;

    /**
     * WeIdentity DID contract object, for calling weIdentity DID contract.
     */
    private static AuthorityIssuerController authorityIssuerController;

    /**
     * WeIdentity DID contract object, for calling weIdentity DID contract.
     */
    private static CptController cptController;
    
    /**
     * 构造函数.
     */
    public RawTransactionServiceEngineV2() {
        if (weIdContract == null || authorityIssuerController == null || cptController == null) {
            reload(); 
        }
    }
    
    /**
     * 重新加载静态合约对象.
     */
    public void reload() {
        weIdContract = getContractService(fiscoConfig.getWeIdAddress(), WeIdContract.class);
        authorityIssuerController = getContractService(fiscoConfig.getIssuerAddress(), 
            AuthorityIssuerController.class); 
        cptController = getContractService(fiscoConfig.getCptAddress(), CptController.class); 
    }

    /**
     * Send a transaction to blockchain through web3j instance using the transactionHex value.
     *
     * @param transactionHex the transactionHex value
     * @return the transactionReceipt
     * @throws Exception the exception
     */
    public static TransactionReceipt sendTransaction(String transactionHex)
        throws Exception {

        SendTransaction ethSendTransaction = getClient().sendRawTransaction(transactionHex);
        if (ethSendTransaction.hasError()) {
            logger.error("Error processing transaction request: "
                + ethSendTransaction.getError().getMessage());
            return null;
        }
        Optional<TransactionReceipt> receiptOptional =
            getTransactionReceiptRequest(ethSendTransaction.getTransactionHash());
        int sumTime = 0;
        try {
            for (int i = 0; i < WeIdConstant.POLL_TRANSACTION_ATTEMPTS; i++) {
                if (!receiptOptional.isPresent()) {
                    Thread.sleep((long) WeIdConstant.POLL_TRANSACTION_SLEEP_DURATION);
                    sumTime += WeIdConstant.POLL_TRANSACTION_SLEEP_DURATION;
                    receiptOptional = getTransactionReceiptRequest(
                        ethSendTransaction.getTransactionHash());
                } else {
                    return receiptOptional.get();
                }
            }
        } catch (Exception e) {
            throw new WeIdBaseException("Transaction receipt was not generated after "
                + ((sumTime) / 1000
                + " seconds for transaction: " + ethSendTransaction));
        }
        return null;
    }

    /**
     * Get a TransactionReceipt request from a transaction Hash.
     *
     * @param web3j the web3j instance to blockchain
     * @param transactionHash the transactionHash value
     * @return the transactionReceipt wrapper
     * @throws Exception the exception
     */
    private static Optional<TransactionReceipt> getTransactionReceiptRequest(
        String transactionHash
    ) throws Exception {
        BcosTransactionReceipt transactionReceipt = getClient()
            .getTransactionReceipt(transactionHash);
        if (transactionReceipt.hasError()) {
            logger.error("Error processing transaction request: "
                + transactionReceipt.getError().getMessage());
            return Optional.empty();
        }
        return transactionReceipt.getTransactionReceipt();
    }

    /**
     * Verify Authority Issuer related events.
     *
     * @param event the Event
     * @param opcode the Opcode
     * @return the ErrorCode
     */
    public static ErrorCode verifyAuthorityIssuerRelatedEvent(
        AuthorityIssuerRetLogEventResponse event,
        Integer opcode) {
        if (event == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (event.addr == null || event.operation == null || event.retCode == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }

        Integer eventOpcode = event.operation.intValue();
        if (eventOpcode.equals(opcode)) {
            Integer eventRetCode = event.retCode.intValue();
            return ErrorCode.getTypeByErrorCode(eventRetCode);
        } else {
            return ErrorCode.AUTHORITY_ISSUER_OPCODE_MISMATCH;
        }
    }

    /**
     * Verify Register CPT related events.
     *
     * @param transactionReceipt the TransactionReceipt
     * @param cptController cptController contract address
     * @return the ErrorCode
     */
    public static ResponseData<CptBaseInfo> resolveRegisterCptEvents(
        TransactionReceipt transactionReceipt,
        CptController cptController) {
        List<RegisterCptRetLogEventResponse> event = cptController.getRegisterCptRetLogEvents(
            transactionReceipt
        );

        if (CollectionUtils.isEmpty(event)) {
            logger.error("[registerCpt] event is empty");
            return new ResponseData<>(null, ErrorCode.CPT_EVENT_LOG_NULL);
        }

        return TransactionUtils.getResultByResolveEvent(
            event.get(0).retCode,
            event.get(0).cptId,
            event.get(0).cptVersion,
            transactionReceipt
        );
    }

    /* (non-Javadoc)
     * @see com.webank.weid.service.impl.engine.RawTransactionServiceEngine
     * #createWeId(java.lang.String)
     */
    @Override
    public ResponseData<String> createWeId(String transactionHex) {
        try {
            TransactionReceipt transactionReceipt = sendTransaction(transactionHex);
            List<WeIdAttributeChangedEventResponse> response =
                weIdContract.getWeIdAttributeChangedEvents(transactionReceipt);
            TransactionInfo info = new TransactionInfo(transactionReceipt);
            if (!CollectionUtils.isEmpty(response)) {
                return new ResponseData<>(Boolean.TRUE.toString(), ErrorCode.SUCCESS, info);
            }
        } catch (Exception e) {
            logger.error("[createWeId] create failed due to unknown transaction error. ", e);
        }
        return new ResponseData<>(StringUtils.EMPTY, ErrorCode.TRANSACTION_EXECUTE_ERROR);
    }

    /* (non-Javadoc)
     * @see com.webank.weid.service.impl.engine.RawTransactionServiceEngine
     * #registerAuthorityIssuer(java.lang.String)
     */
    @Override
    public ResponseData<String> registerAuthorityIssuer(String transactionHex) {
        try {
            TransactionReceipt transactionReceipt = sendTransaction(transactionHex);

            List<AuthorityIssuerRetLogEventResponse> eventList =
                authorityIssuerController.getAuthorityIssuerRetLogEvents(transactionReceipt);
            AuthorityIssuerRetLogEventResponse event = eventList.get(0);
            TransactionInfo info = new TransactionInfo(transactionReceipt);
            ErrorCode errorCode = verifyAuthorityIssuerRelatedEvent(event,
                WeIdConstant.ADD_AUTHORITY_ISSUER_OPCODE);
            Boolean result = errorCode.getCode() == ErrorCode.SUCCESS.getCode();
            return new ResponseData<>(result.toString(), errorCode, info);
        } catch (Exception e) {
            logger.error("[registerAuthorityIssuer] register failed due to transaction error.", e);
        }
        return new ResponseData<>(StringUtils.EMPTY, ErrorCode.TRANSACTION_EXECUTE_ERROR);
    }

    /* (non-Javadoc)
     * @see com.webank.weid.service.impl.engine.RawTransactionServiceEngine
     * #registerCpt(java.lang.String)
     */
    @Override
    public ResponseData<String> registerCpt(String transactionHex) {
        try {
            TransactionReceipt transactionReceipt = sendTransaction(transactionHex);
            CptBaseInfo cptBaseInfo =
                resolveRegisterCptEvents(
                    transactionReceipt,
                    cptController
                ).getResult();

            TransactionInfo info = new TransactionInfo(transactionReceipt);
            if (cptBaseInfo != null) {
                return new ResponseData<>(DataToolUtils.objToJsonStrWithNoPretty(cptBaseInfo),
                    ErrorCode.SUCCESS, info);
            }
        } catch (Exception e) {
            logger.error("[registerCpt] register failed due to unknown transaction error. ", e);
        }
        return new ResponseData<>(StringUtils.EMPTY, ErrorCode.TRANSACTION_EXECUTE_ERROR);
    }

}
