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

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.zip.DataFormatException;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.abi.EventEncoder;
import org.fisco.bcos.sdk.client.protocol.response.BcosTransactionReceiptsDecoder;
import org.fisco.bcos.sdk.crypto.CryptoSuite;
import org.fisco.bcos.sdk.model.CryptoType;
import org.fisco.bcos.sdk.model.TransactionReceipt;
import org.fisco.bcos.sdk.model.TransactionReceipt.Logs;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.ResolveEventLogStatus;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.constant.WeIdConstant.PublicKeyType;
import com.webank.weid.constant.WeIdEventConstant;
import com.webank.weid.contract.v2.WeIdContract;
import com.webank.weid.contract.v2.WeIdContract.WeIdAttributeChangedEventResponse;
import com.webank.weid.contract.v2.WeIdContract.WeIdHistoryEventEventResponse;
import com.webank.weid.exception.DataTypeCastException;
import com.webank.weid.exception.ResolveAttributeException;
import com.webank.weid.exception.WeIdBaseException;
import com.webank.weid.protocol.base.AuthenticationProperty;
import com.webank.weid.protocol.base.PublicKeyProperty;
import com.webank.weid.protocol.base.ServiceProperty;
import com.webank.weid.protocol.base.WeIdDocument;
import com.webank.weid.protocol.base.WeIdPojo;
import com.webank.weid.protocol.response.ResolveEventLogResult;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.protocol.response.TransactionInfo;
import com.webank.weid.service.impl.engine.BaseEngine;
import com.webank.weid.service.impl.engine.WeIdServiceEngine;
import com.webank.weid.util.DataToolUtils;
import com.webank.weid.util.DateUtils;
import com.webank.weid.util.WeIdUtils;

/**
 * WeIdServiceEngine call weid contract which runs on FISCO BCOS 2.0.
 *
 * @author tonychen 2019年6月21日
 */
public class WeIdServiceEngineV2 extends BaseEngine implements WeIdServiceEngine {

    private static final Logger logger = LoggerFactory.getLogger(WeIdServiceEngineV2.class);

    /**
     * The topic map.
     */
    private static final HashMap<String, String> topicMap;

    /**
     * Block number for stopping parsing.
     */
    private static final int STOP_RESOLVE_BLOCK_NUMBER = 0;

    /**
     * WeIdentity DID contract object, for calling weIdentity DID contract.
     */
    private static WeIdContract weIdContract;

    static {
        // initialize the event topic
        topicMap = new HashMap<String, String>();

        topicMap.put(
            new EventEncoder(new CryptoSuite(CryptoType.ECDSA_TYPE)).encode(
                WeIdContract.WEIDATTRIBUTECHANGED_EVENT
            ),
            WeIdEventConstant.WEID_EVENT_ATTRIBUTE_CHANGE
        );
    }

    /**
     * 构造函数.
     */
    public WeIdServiceEngineV2() {
        if (weIdContract == null) {
            reload();
        }
    }

    /**
     * 重新加载静态合约对象.
     */
    @Override
    public void reload() {
        weIdContract = getContractService(fiscoConfig.getWeIdAddress(), WeIdContract.class);
    }

    /* (non-Javadoc)
     * @see com.webank.weid.service.impl.engine.WeIdController#isWeIdExist(java.lang.String)
     */
    @Override
    public ResponseData<Boolean> isWeIdExist(String weId) {
        try {

            boolean isExist = weIdContract
                .isIdentityExist(WeIdUtils.convertWeIdToAddress(weId)).booleanValue();
            return new ResponseData<>(isExist, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("[isWeIdExist] execute failed. Error message :{}", e);
            return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * Resolve the event history given weId as key, reversely from on-chain linked blocks.
     *
     * @param weId WeID as key
     * @param blockNumber the current latest block number
     * @param blockList stored block height list
     * @param blockEventMap stored block event map
     */
    private static void resolveEventHistory(
        String weId,
        int blockNumber,
        List<Integer> blockList,
        Map<Integer, List<WeIdAttributeChangedEventResponse>> blockEventMap
    ) {
        int previousBlock = blockNumber;
        while (previousBlock != STOP_RESOLVE_BLOCK_NUMBER) {
            int currentBlockNumber = previousBlock;
            // Fill-in blockList
            blockList.add(currentBlockNumber);
            previousBlock = 0;
            try {
                List<TransactionReceipt> receipts = getTransactionReceipts(currentBlockNumber);
                for (TransactionReceipt receipt : receipts) {
                    List<Logs> logs = receipt.getLogs();
                    for (Logs log : logs) {
                        ResolveEventLogResult returnValue =
                            resolveSingleEventLog(weId, log, receipt, currentBlockNumber,
                                blockEventMap);
                        if (returnValue.getResultStatus().equals(
                            ResolveEventLogStatus.STATUS_SUCCESS)) {
                            if (returnValue.getPreviousBlock() == currentBlockNumber) {
                                continue;
                            }
                            previousBlock = returnValue.getPreviousBlock();
                        }
                    }
                }
            } catch (IOException | DataTypeCastException | DataFormatException e) {
                logger.error(
                    "[resolveEventHistory]: get TransactionReceipt by weId :{} failed.", weId, e);
                throw new ResolveAttributeException(
                    ErrorCode.TRANSACTION_EXECUTE_ERROR.getCode(),
                    ErrorCode.TRANSACTION_EXECUTE_ERROR.getCodeDesc(),
                    e);
            }
        }
    }

    private static ResolveEventLogResult resolveSingleEventLog(
        String weId,
        Logs log,
        TransactionReceipt receipt,
        int currentBlockNumber,
        Map<Integer, List<WeIdAttributeChangedEventResponse>> blockEventMap
    ) {
        String topic = log.getTopics().get(0);
        String event = topicMap.get(topic);

        if (StringUtils.isNotBlank(event)) {
            return extractEventsFromBlock(weId, receipt, currentBlockNumber, blockEventMap);
        }
        ResolveEventLogResult response = new ResolveEventLogResult();
        response.setResolveEventLogStatus(ResolveEventLogStatus.STATUS_EVENT_NULL);
        return response;
    }


    private static ResolveEventLogResult extractEventsFromBlock(
        String weId,
        TransactionReceipt receipt,
        int currentBlockNumber,
        Map<Integer, List<WeIdAttributeChangedEventResponse>> blockEventMap
    ) {

        List<WeIdAttributeChangedEventResponse> eventlog =
            weIdContract.getWeIdAttributeChangedEvents(receipt);
        ResolveEventLogResult response = new ResolveEventLogResult();

        if (CollectionUtils.isEmpty(eventlog)) {
            response.setResolveEventLogStatus(ResolveEventLogStatus.STATUS_EVENTLOG_NULL);
            return response;
        }

        int previousBlock = 0;
        for (WeIdAttributeChangedEventResponse res : eventlog) {
            if (res.identity == null || res.updated == null || res.previousBlock == null) {
                response.setResolveEventLogStatus(ResolveEventLogStatus.STATUS_RES_NULL);
                return response;
            }

            String identity = res.identity.toString();
            String weAddress = WeIdUtils.convertWeIdToAddress(weId);
            if (!StringUtils.equals(weAddress, identity)) {
                response.setResolveEventLogStatus(ResolveEventLogStatus.STATUS_KEY_NOT_MATCH);
                return response;
            }

            // Fill-in blockEventMap
            List<WeIdAttributeChangedEventResponse> events = blockEventMap.get(currentBlockNumber);
            if (CollectionUtils.isEmpty(events)) {
                List<WeIdAttributeChangedEventResponse> newEvents = new ArrayList<>();
                newEvents.add(res);
                blockEventMap.put(currentBlockNumber, newEvents);
            } else {
                events.add(res);
            }

            //String key = new String(res.key);
            //String value = new String(res.value);
            previousBlock = res.previousBlock.intValue();
        }

        response.setPreviousBlock(previousBlock);
        response.setResolveEventLogStatus(ResolveEventLogStatus.STATUS_SUCCESS);
        return response;
    }

    /* (non-Javadoc)
     * @see com.webank.weid.service.impl.engine.WeIdController#getWeIdDocument(java.lang.String)
     */
    @Override
    public ResponseData<WeIdDocument> getWeIdDocument(String weId) {
        Map<Integer, List<WeIdAttributeChangedEventResponse>> blockEventMap = new HashMap<>();
        List<Integer> blockList = new ArrayList<>();
        WeIdDocument result = new WeIdDocument();
        result.setId(weId);
        int latestBlockNumber = 0;
        try {
            String identityAddr = WeIdUtils.convertWeIdToAddress(weId);
            latestBlockNumber = weIdContract
                .getLatestRelatedBlock(identityAddr).intValue();
            if (0 == latestBlockNumber) {
                return new ResponseData<>(null, ErrorCode.WEID_DOES_NOT_EXIST);
            }

            // Step 1: fetch all blocks in this event link in REVERSE order from chain
            resolveEventHistory(weId, latestBlockNumber, blockList, blockEventMap);

            // Step 2: reverse this the block list (so it is ascending order now)
            Collections.reverse(blockList);

            // Step 3: construct WeID Document in NORMAL order off-chain
            constructWeIdDocument(blockList, blockEventMap, result);

            return new ResponseData<>(result, ErrorCode.SUCCESS);
        } catch (ResolveAttributeException e) {
            logger.error("[getWeIdDocument]: resolveTransaction failed. "
                    + "weId: {}, errorCode:{}",
                weId,
                e.getErrorCode(),
                e);
            return new ResponseData<WeIdDocument>(result,
                ErrorCode.getTypeByErrorCode(e.getErrorCode()));
        } catch (Exception e) {
            logger.error("[getWeIdDocument]: exception.", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    private void constructWeIdDocument(
        List<Integer> blockList,
        Map<Integer, List<WeIdAttributeChangedEventResponse>> blockEventMap,
        WeIdDocument weIdDocument) {
        String weId = weIdDocument.getId();
        // Iterate thru the blocklist (now ascending)
        for (int block : blockList) {
            List<WeIdAttributeChangedEventResponse> eventList = blockEventMap.get(block);
            for (WeIdAttributeChangedEventResponse event : eventList) {
                String key = new String(event.key);
                String value = new String(event.value);
                constructWeIdAttribute(key, value, weId, weIdDocument);
            }
        }
    }

    /**
     * Identify the event and construct WeID Document.
     *
     * @param key the key
     * @param value the value (mainly pubkeys including tag)
     * @param weId the weId
     * @param result the updating Document
     */
    private static void constructWeIdAttribute(
        String key, String value, String weId, WeIdDocument result) {
        if (StringUtils.startsWith(key, WeIdConstant.WEID_DOC_PUBLICKEY_PREFIX)) {
            constructWeIdPublicKeys(key, value, weId, result);
        } else if (StringUtils.startsWith(key, WeIdConstant.WEID_DOC_AUTHENTICATE_PREFIX)) {
            if (!value.contains(WeIdConstant.REMOVED_PUBKEY_TAG)) {
                constructWeIdPublicKeys(null, value, weId, result);
            }
            constructWeIdAuthentication(value, weId, result);
        } else if (StringUtils.startsWith(key, WeIdConstant.WEID_DOC_SERVICE_PREFIX)) {
            constructWeIdService(key, value, weId, result);
        } else {
            constructDefaultWeIdAttribute(key, value, weId, result);
        }
    }

    private static void constructWeIdPublicKeys(String key, String value, String weId,
        WeIdDocument result) {

        logger.info("method constructWeIdPublicKeys() parameter::value:{}, weId:{}, "
            + "result:{}", value, weId, result);
        List<PublicKeyProperty> pubkeyList = result.getPublicKey();

        String type = PublicKeyType.SECP256K1.getTypeName();
        // Identify explicit type from key
        if (!StringUtils.isEmpty(key)) {
            String[] keyArray = StringUtils.splitByWholeSeparator(key, "/");
            if (keyArray.length > 2) {
                type = keyArray[2];
            }
        }

        // In ascending order approach, we use the new obtained value as overriding attribute.
        // We 1st: UDPATE STATUS, by going thru the existing pubkeys list. If it already contains
        // this pubkey, simply override the tag and return.
        Boolean isRevoked = value.contains(WeIdConstant.REMOVED_PUBKEY_TAG);
        String trimmedPubKey = StringUtils
            .splitByWholeSeparator(value.replace(WeIdConstant.REMOVED_PUBKEY_TAG, ""),
                WeIdConstant.SEPARATOR)[0];
        for (PublicKeyProperty pr : pubkeyList) {
            if (pr.getPublicKey().contains(trimmedPubKey)) {
                // update status: revocation
                if (!pr.getRevoked().equals(isRevoked)) {
                    pr.setRevoked(isRevoked);
                }
                // update owner
                String[] publicKeyData = StringUtils
                    .splitByWholeSeparator(value, WeIdConstant.SEPARATOR);
                String weAddress = publicKeyData[1];
                String owner = WeIdUtils.convertAddressToWeId(weAddress);
                pr.setOwner(owner);
                return;
            }
        }

        // 由于目前不允许对一个不存在的key直接remove，因此下面这小段不会被执行到。未来修改时需要留意。
        if (isRevoked) {
            logger.error("Failed to revoke a non-existent pubkey {} from current Document {}",
                value, result);
            return;
        }

        // We 2nd: not an UPDATE case, now CREATE a new pubkey property and allocate a new ID.
        PublicKeyProperty pubKey = new PublicKeyProperty();
        pubKey.setId(
            new StringBuffer()
                .append(weId)
                .append("#keys-")
                .append(result.getPublicKey().size())
                .toString()
        );
        String[] publicKeyData = StringUtils.splitByWholeSeparator(value, WeIdConstant.SEPARATOR);
        if (publicKeyData != null && publicKeyData.length == 2) {
            pubKey.setPublicKey(publicKeyData[0]);
            String weAddress = publicKeyData[1];
            String owner = WeIdUtils.convertAddressToWeId(weAddress);
            pubKey.setOwner(owner);
        }
        pubKey.setType(type);
        result.getPublicKey().add(pubKey);
    }

    private static void constructWeIdAuthentication(
        String value,
        String weId,
        WeIdDocument result
    ) {
        logger.info("method buildWeIdAuthentication() parameter::value:{}, weId:{}, "
            + "result:{}", value, weId, result);
        List<PublicKeyProperty> keyList = result.getPublicKey();
        List<AuthenticationProperty> authList = result.getAuthentication();

        // In ascending order approach, we use the similar approach as in pubkey - always override.

        // We 1st: UDPATE STATUS, by going thru the existing auths list. If it already contains
        // this auth, simply override the tag and return.
        // Complexity here is: 1. the ID must follow public key. 2. enable tag case.
        Boolean isRevoked = value.contains(WeIdConstant.REMOVED_AUTHENTICATION_TAG);
        for (AuthenticationProperty ap : authList) {
            String pubKeyId = ap.getPublicKey();
            for (PublicKeyProperty pkp : keyList) {
                if (pubKeyId.equalsIgnoreCase(pkp.getId()) && value.contains(pkp.getPublicKey())) {
                    // Found matching, now do tag resetting
                    // NOTE: 如果isRevoked为false，请注意由于pubKey此时一定已经是false（见母方法），
                    //  故无需做特别处理。但，未来如果实现分离了，就需要做特殊处理，还请留意。
                    if (!ap.getRevoked().equals(isRevoked)) {
                        ap.setRevoked(isRevoked);
                    }
                    return;
                }
            }
        }

        // 由于目前不允许对一个不存在的key直接remove，因此下面这小段不会被执行到。未来修改时需要留意。
        if (isRevoked) {
            logger.error("Failed to revoke a non-existent auth {} from current Document {}",
                value, result);
            return;
        }

        // We 2nd: create new one when no matching record is found
        AuthenticationProperty auth = new AuthenticationProperty();
        for (PublicKeyProperty r : keyList) {
            if (value.contains(r.getPublicKey())) {
                for (AuthenticationProperty ar : authList) {
                    if (StringUtils.equals(ar.getPublicKey(), r.getId())) {
                        return;
                    }
                }
                auth.setPublicKey(r.getId());
                result.getAuthentication().add(auth);
            }
        }
    }

    private static void constructWeIdService(String key, String value, String weId,
        WeIdDocument result) {

        logger.info("method buildWeIdService() parameter::key{}, value:{}, weId:{}, "
            + "result:{}", key, value, weId, result);
        String service = StringUtils.splitByWholeSeparator(key, "/")[2];
        List<ServiceProperty> serviceList = result.getService();

        // Always override when new value is obtained
        for (ServiceProperty sr : serviceList) {
            if (service.equals(sr.getType())) {
                sr.setServiceEndpoint(value);
                return;
            }
        }
        ServiceProperty serviceResult = new ServiceProperty();
        serviceResult.setType(service);
        serviceResult.setServiceEndpoint(value);
        result.getService().add(serviceResult);
    }

    private static void constructDefaultWeIdAttribute(
        String key, String value, String weId, WeIdDocument result) {

        logger.info("method buildWeIdAttributeDefault() parameter::key{}, value:{}, weId:{}, "
            + "result:{}", key, value, weId, result);
        switch (key.trim()) {
            case WeIdConstant.WEID_DOC_CREATED:
                result.setCreated(Long.valueOf(value));
                break;
            default:
                break;
        }
    }

    /* (non-Javadoc)
     * @see com.webank.weid.service.impl.engine.WeIdController
     * #createWeId(java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public ResponseData<Boolean> createWeId(
        String weAddress,
        String publicKey,
        String privateKey,
        boolean isDelegate) {

        String auth = new StringBuffer()
            .append(publicKey)
            .append(WeIdConstant.SEPARATOR)
            .append(weAddress)
            .toString();
        String created = DateUtils.getNoMillisecondTimeStampString();
        TransactionReceipt receipt;
        WeIdContract weIdContract =
            reloadContract(fiscoConfig.getWeIdAddress(), privateKey, WeIdContract.class);
        try {
            if (isDelegate) {
                receipt = weIdContract.delegateCreateWeId(
                    weAddress,
                    DataToolUtils.stringToByteArray(auth),
                    DataToolUtils.stringToByteArray(created),
                    BigInteger.valueOf(DateUtils.getNoMillisecondTimeStamp())
                );
            } else {

                receipt = weIdContract.createWeId(
                    weAddress,
                    DataToolUtils.stringToByteArray(auth),
                    DataToolUtils.stringToByteArray(created),
                    BigInteger.valueOf(DateUtils.getNoMillisecondTimeStamp())
                );
            }

            TransactionInfo info = new TransactionInfo(receipt);
            List<WeIdAttributeChangedEventResponse> response =
                weIdContract.getWeIdAttributeChangedEvents(receipt);
            if (CollectionUtils.isEmpty(response)) {
                logger.error(
                    "The input private key does not match the current weid, operation of "
                        + "modifying weid is not allowed. we address is {}",
                    weAddress
                );
                return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH, info);
            }
            return new ResponseData<>(true, ErrorCode.SUCCESS, info);
        } catch (Exception e) {
            logger.error("[createWeId] create weid has error, Error Message：{}", e);
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH);
        }
    }

    /* (non-Javadoc)
     * @see com.webank.weid.service.impl.engine.WeIdController
     * #setAttribute(java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public ResponseData<Boolean> setAttribute(
        String weAddress,
        String attributeKey,
        String value,
        String privateKey,
        boolean isDelegate) {

        try {
            WeIdContract weIdContract =
                reloadContract(fiscoConfig.getWeIdAddress(), privateKey, WeIdContract.class);
            byte[] attrValue = value.getBytes();
            BigInteger updated = BigInteger.valueOf(DateUtils.getNoMillisecondTimeStamp());
            TransactionReceipt transactionReceipt = null;
            if (isDelegate) {
                transactionReceipt = weIdContract.delegateSetAttribute(
                    weAddress,
                    DataToolUtils.stringToByte32Array(attributeKey),
                    attrValue,
                    updated
                );
            } else {
                transactionReceipt =
                    weIdContract.setAttribute(
                        weAddress,
                        DataToolUtils.stringToByte32Array(attributeKey),
                        attrValue,
                        updated
                    );
            }

            TransactionInfo info = new TransactionInfo(transactionReceipt);
            List<WeIdAttributeChangedEventResponse> response =
                weIdContract.getWeIdAttributeChangedEvents(transactionReceipt);
            if (CollectionUtils.isNotEmpty(response)) {
                return new ResponseData<>(true, ErrorCode.SUCCESS, info);
            } else {
                return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH,
                    info);
            }
        } catch (Exception e) {
            logger.error("[setAttribute] set Attribute has error, Error Message：{}", e);
            return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
        }
    }

    private static List<TransactionReceipt> getTransactionReceipts(Integer blockNumber) 
        throws IOException, DataFormatException {
        BcosTransactionReceiptsDecoder blockTransactionReceipts = null;
        try {
            blockTransactionReceipts = getClient().getBatchReceiptsByBlockNumberAndRange(
               BigInteger.valueOf(blockNumber), "0", "-1");
        } catch (Exception e) {
            logger.error("[getTransactionReceipts] get block {} err: {}", blockNumber, e);
        }
        if (blockTransactionReceipts == null) {
            logger.info("[getTransactionReceipts] get block {} err: is null", blockNumber);
            throw new WeIdBaseException("the transactionReceipts is null.");
        }
        
        return blockTransactionReceipts.decodeTransactionReceiptsInfo().getTransactionReceipts();
    }

    private List<WeIdPojo> getWeIdListByBlockNumber(Integer blockNumber) {
        // 根据块高获取当前块里面的所有weId
        List<WeIdPojo> result = new ArrayList<WeIdPojo>();
        try {
            List<TransactionReceipt> receipts = getTransactionReceipts(blockNumber);
            int index = 0;
            for (TransactionReceipt receipt : receipts) {
                List<WeIdHistoryEventEventResponse> eventlog =
                    weIdContract.getWeIdHistoryEventEvents(receipt);
                if (CollectionUtils.isEmpty(eventlog)) {
                    continue;
                }
                for (WeIdHistoryEventEventResponse res : eventlog) {
                    WeIdPojo pojo = new WeIdPojo();
                    pojo.setId(WeIdUtils.convertAddressToWeId(res.identity));
                    pojo.setCreated(res.created.longValue());
                    pojo.setCurrentBlockNum(blockNumber);
                    pojo.setPreviousBlockNum(res.previousBlock.intValue());
                    boolean isExist = weIdContract
                        .isIdentityExist(WeIdUtils.convertWeIdToAddress(pojo.getId()))
                        
                        .booleanValue();
                    if (isExist) {
                        pojo.setIndex(index);
                        result.add(pojo);
                        index++;
                    }
                }
            }
        } catch (Exception e) {
            logger.error(
                "[getWeIdListByBlockNumber]: get WeIdList By BlockNumber :{} failed.", 
                blockNumber, 
                e
            );
            throw new ResolveAttributeException(
                ErrorCode.TRANSACTION_EXECUTE_ERROR.getCode(),
                ErrorCode.TRANSACTION_EXECUTE_ERROR.getCodeDesc(),
                e);
        }
        return result;
    }

    /**
     * get the first blockNumber for the contract.
     * 
     * @return the blockNumber
     * @throws Exception unknown exception
     */
    private Integer getFirstBlockNum() throws Exception {
        return weIdContract.getFirstBlockNum().intValue();
    }

    /**
     * get the last blockNumber for the contract.
     * @return the blockNumber
     * @throws Exception unknown exception
     */
    private Integer getLatestBlockNum() throws Exception {
        return weIdContract.getLatestBlockNum().intValue();
    }

    /**
     * get the next blockNumber by the currentBlockNumber.
     * @param blockNumber the currentBlockNumber
     * @return the blockNumber
     * @throws Exception unknown exception
     */
    private Integer getNextBlockNum(Integer blockNumber) throws Exception {
        return weIdContract.getNextBlockNumByBlockNum(
                new BigInteger(String.valueOf(blockNumber))
            ).intValue();
    }

    @Override
    public ResponseData<List<WeIdPojo>> getWeIdList(
        Integer blockNumber,
        Integer pageSize,
        Integer indexInBlock,
        boolean direction
    ) throws Exception {
        LinkedList<WeIdPojo> result = new LinkedList<WeIdPojo>();
        if (pageSize == null || indexInBlock == null || blockNumber == null) {
            return new ResponseData<>(result, ErrorCode.ILLEGAL_INPUT);
        }
        if (pageSize <= 0) {
            return new ResponseData<>(result, ErrorCode.SUCCESS);
        }
        // 处理块高
        Integer firstBlockNumer = this.getFirstBlockNum();
        Integer latestBlockNumer = this.getLatestBlockNum();
        if (blockNumber < firstBlockNumer) {
            blockNumber = firstBlockNumer;
        } else if (blockNumber > latestBlockNumer) {
            blockNumber = latestBlockNumer;
        }
        // 根据当前块高查找weidList
        Integer queryBlockNumber = blockNumber;
        Integer beginIndex = indexInBlock;
        boolean changeBlock = false;//是否换块
        outer: do {
            if (changeBlock && queryBlockNumber == 0) {
                break;
            }
            List<WeIdPojo> weIdListByBlockNumber = this.getWeIdListByBlockNumber(queryBlockNumber);
            // 根据方向判断
            if (direction) {
                if (weIdListByBlockNumber.size() == 0) {
                    // 说明根据块高没有查询出数据，此时也无法向前查询了直接返回
                    break;
                }
                // 如果是正向的 表示往前检索
                if (changeBlock) { 
                    // 表示已换块查询
                    beginIndex = weIdListByBlockNumber.size() - 1;
                } else {
                    // 没换块
                    // 如果index大于当前块最大位置 则index为当前最大位置
                    if (beginIndex > weIdListByBlockNumber.size() - 1) {
                        beginIndex = weIdListByBlockNumber.size() - 1;
                    }
                }
                for (int i = beginIndex; i >= 0; i--) {
                    WeIdPojo pojo = weIdListByBlockNumber.get(i);
                    result.add(pojo);
                    // 指定下一个查询块
                    queryBlockNumber = pojo.getPreviousBlockNum();
                    if (result.size() == pageSize || queryBlockNumber == firstBlockNumer) { 
                        // 说明够数了 或者已查询第一个块高
                        break outer;
                    }
                }
                if (beginIndex < 0) {
                    // 指定下一个查询块
                    queryBlockNumber = weIdListByBlockNumber.get(0).getPreviousBlockNum();
                    if (queryBlockNumber == firstBlockNumer) { 
                        // 说明已查询第一个块高
                        break;
                    }
                }
                // 换块
                changeBlock = true;
            } else {
                if (weIdListByBlockNumber.size() == 0) {
                    // 说明根据块高没有查询出数据
                    // 换块
                    queryBlockNumber = this.getNextBlockNum(queryBlockNumber);
                    changeBlock = true;
                    continue;
                }
                if (changeBlock) {
                    beginIndex = 0; 
                } else {
                    if (beginIndex < 0) {
                        beginIndex = 0;
                    }
                    if (beginIndex > weIdListByBlockNumber.size() - 1) {
                        // 换块
                        queryBlockNumber = this.getNextBlockNum(queryBlockNumber);
                        changeBlock = true;
                        continue;
                    }
                }
                // 如果是反向的 表示往后检索
                for (int i = beginIndex; i < weIdListByBlockNumber.size(); i++) {
                    WeIdPojo pojo = weIdListByBlockNumber.get(i);
                    result.addFirst(pojo);
                    if (result.size() == pageSize) { 
                        // 说明够数了
                        break outer;
                    }
                }
                // 换块
                queryBlockNumber = this.getNextBlockNum(queryBlockNumber);
                changeBlock = true;
            }
        } while (true);
        return new ResponseData<>(result, ErrorCode.SUCCESS);
    }

    @Override
    public ResponseData<Integer> getWeIdCount() {
        try {
            Integer total = weIdContract.getWeIdCount().intValue();
            return new ResponseData<>(total, ErrorCode.SUCCESS); 
        } catch (Exception e) {
            logger.error("[getWeIdTotal]: get weId total has unknow error. ", e);
            return new ResponseData<>(0, ErrorCode.UNKNOW_ERROR);
        }
    }
}
