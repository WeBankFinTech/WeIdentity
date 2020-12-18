package com.webank.weid.service.impl.engine.fiscov2;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.abi.datatypes.generated.Bytes32;
import org.fisco.bcos.sdk.abi.datatypes.generated.tuples.generated.Tuple2;
import org.fisco.bcos.sdk.abi.datatypes.generated.tuples.generated.Tuple4;
import org.fisco.bcos.sdk.model.TransactionReceipt;
import org.fisco.bcos.sdk.transaction.codec.decode.TransactionDecoderInterface;
import org.fisco.bcos.sdk.transaction.codec.decode.TransactionDecoderService;
import org.fisco.bcos.sdk.transaction.model.dto.TransactionResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.CnsType;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.ParamKeyConstant;
import com.webank.weid.contract.v2.DataBucket;
import com.webank.weid.protocol.base.HashContract;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.service.impl.engine.BaseEngine;
import com.webank.weid.service.impl.engine.DataBucketServiceEngine;
import com.webank.weid.util.DataToolUtils;
import com.webank.weid.util.WeIdUtils;

public class DataBucketServiceEngineV2 extends BaseEngine implements DataBucketServiceEngine {

    private static final Logger logger = LoggerFactory.getLogger(DataBucketServiceEngineV2.class);

    private DataBucket dataBucket;
    private CnsType cnsType;
    private TransactionDecoderInterface transactionDecoder;

    /**
     * 构造函数.
     * 
     * @param cnsType cns类型枚举
     */
    public DataBucketServiceEngineV2(CnsType cnsType) {
        this.cnsType = cnsType;
        loadDataBucket();
    }

    private void loadDataBucket() {
        if (dataBucket == null) {
            dataBucket = super.getContractService(
                getBucketByCns(cnsType).getAddress(), 
                DataBucket.class
            );
        }
    }

    private DataBucket getDataBucket(WeIdPrivateKey privateKey) {
        return super.reloadContract(
            getBucketByCns(cnsType).getAddress(), 
            privateKey, 
            DataBucket.class
        );
    }

    private TransactionDecoderInterface getTransactionDecoder() {
        if (transactionDecoder == null) {
            transactionDecoder = new TransactionDecoderService(getClient().getCryptoSuite());
        }
        return transactionDecoder;
    }

    @Override
    public ResponseData<Boolean> put(
        String bucketId, 
        String key, 
        String value, 
        WeIdPrivateKey privateKey) {
        
        Bytes32 keyByte32 = DataToolUtils.bytesArrayToBytes32(key.getBytes());
        try {
            TransactionReceipt receipt = getDataBucket(privateKey).put(
                bucketId, keyByte32.getValue(), value);
            if (StringUtils
                .equals(receipt.getStatus(), ParamKeyConstant.TRNSACTION_RECEIPT_STATUS_SUCCESS)) {
                logger.info("[put] put [{}:{}] into chain success, bucketId is {}.", 
                    key, value, bucketId);
                ErrorCode  code = analysisErrorCode(receipt, DataBucket.FUNC_PUT);
                return new ResponseData<Boolean>(code == ErrorCode.SUCCESS, code);
            }
            logger.error("[put] put [{}:{}] into chain fail, bucketId is {}.", 
                key, value, bucketId);
            return new ResponseData<Boolean>(false, ErrorCode.TRANSACTION_EXECUTE_ERROR);
        } catch (Exception e) {
            logger.error("[put] put [{}:{}] into chain has excpetion, bucketId is {}, exception:",
                key, value, bucketId, e);
            return new ResponseData<Boolean>(false, ErrorCode.UNKNOW_ERROR);
        }
    }

    private ErrorCode analysisErrorCode(TransactionReceipt receipt, String functionName) {
        ErrorCode errorCode = ErrorCode.UNKNOW_ERROR;
        try {
            TransactionResponse transactionResponse = getTransactionDecoder()
                .decodeReceiptWithValues(DataBucket.ABI, functionName, receipt);
            Integer code = Integer.parseInt(transactionResponse.getValuesList().get(0).toString());
            switch (code.intValue()) {
                case 100:
                    errorCode = ErrorCode.SUCCESS;
                    break;
                case 101:
                    errorCode = ErrorCode.CNS_NO_PERMISSION;
                    break;
                case 102:
                    errorCode = ErrorCode.CNS_DOES_NOT_EXIST;
                    break;
                case 103:
                    errorCode = ErrorCode.CNS_IS_USED;
                    break;
                case 104:
                    errorCode = ErrorCode.CNS_IS_NOT_USED;
                    break;
                default:
                    errorCode = ErrorCode.CNS_CODE_UNDEFINED;
                    break;
            }
            return errorCode;
        } catch (Exception e) {
            logger.error("[analysisErrorCode] has some error!", e);
            return errorCode;
        } finally {
            logger.info("[analysisErrorCode] decode transaction result:{}-{}", 
                errorCode.getCode(), errorCode.getCodeDesc()); 
        }
    }

    @Override
    public ResponseData<String> get(String bucketId, String key) {
        Bytes32 keyByte32 = DataToolUtils.bytesArrayToBytes32(key.getBytes());
        try {
            Tuple2<BigInteger, String> tuple = dataBucket.get(
                bucketId, keyByte32.getValue());
            int code = tuple.getValue1().intValue();
            if (code == 102) {
                logger.error("[get] the bucketId does not exits, bucketId is {}.", bucketId);
                return new ResponseData<String>(StringUtils.EMPTY, ErrorCode.CNS_DOES_NOT_EXIST);
            }
            logger.info("[get] get address successfully, bucketId: {}, key: {}, value: {}", 
                bucketId, key, tuple.getValue2());
            return new ResponseData<String>(tuple.getValue2(), ErrorCode.SUCCESS);  
        } catch (Exception e) {
            logger.error(
                "[get] get data has exception, bucketId is {}, key is {}, exception:", 
                 bucketId, key, e);
            return new ResponseData<String>(StringUtils.EMPTY, ErrorCode.UNKNOW_ERROR);
        }
    }

    @Override
    public ResponseData<Boolean> removeExtraItem(
        String bucketId, 
        String key, 
        WeIdPrivateKey privateKey
    ) {
        Bytes32 keyByte32 = null;
        if (key == null) {
            keyByte32 = DataToolUtils.bytesArrayToBytes32(StringUtils.EMPTY.getBytes());
        } else {
            keyByte32 = DataToolUtils.bytesArrayToBytes32(key.getBytes());
        }
        try {
            logger.info("[remove] remove Extra Item, bucketId is {}, key is {}.", bucketId, key);
            TransactionReceipt receipt = getDataBucket(privateKey).removeExtraItem(
                bucketId, keyByte32.getValue());
            if (StringUtils
                .equals(receipt.getStatus(), ParamKeyConstant.TRNSACTION_RECEIPT_STATUS_SUCCESS)) {
                logger.info("[remove] remove {} from chain success, bucketId is {}.", 
                    key, bucketId);
                ErrorCode  code = analysisErrorCode(receipt, DataBucket.FUNC_REMOVEEXTRAITEM);
                return new ResponseData<Boolean>(code == ErrorCode.SUCCESS, code);
            }
            logger.error("[remove] remove {} from chain fail, bucketId is {}.", key, bucketId);
            return new ResponseData<Boolean>(false, ErrorCode.TRANSACTION_EXECUTE_ERROR);
        } catch (Exception e) {
            logger.error("[remove] remove {} from chain has excpetion, bucketId is {}, exception:",
                key, bucketId, e);
            return new ResponseData<Boolean>(false, ErrorCode.UNKNOW_ERROR);
        }
    }
    
    @Override
    public ResponseData<Boolean> removeDataBucketItem(
        String bucketId, 
        boolean force, 
        WeIdPrivateKey privateKey
    ) {
        try {
            logger.info("[remove] remove Bucket Item, bucketId is {}, force is {}.", 
                bucketId, force);
            TransactionReceipt receipt = getDataBucket(privateKey)
                .removeDataBucketItem(bucketId, force);
            if (StringUtils
                .equals(receipt.getStatus(), ParamKeyConstant.TRNSACTION_RECEIPT_STATUS_SUCCESS)) {
                logger.info("[remove] remove Bucket Item from chain success, bucketId is {}.", 
                    bucketId);
                ErrorCode  code = analysisErrorCode(receipt, DataBucket.FUNC_REMOVEDATABUCKETITEM);
                return new ResponseData<Boolean>(code == ErrorCode.SUCCESS, code);
            }
            logger.error("[remove] remove Bucket Item from chain fail, bucketId is {}.", bucketId);
            return new ResponseData<Boolean>(false, ErrorCode.TRANSACTION_EXECUTE_ERROR);
        } catch (Exception e) {
            logger.error(
                "[remove] remove Bucket Item from chain has excpetion, bucketId is {}, exception:",
                bucketId, 
                e
            );
            return new ResponseData<Boolean>(false, ErrorCode.UNKNOW_ERROR);
        }
    }
    
    @Override
    public ResponseData<Boolean> enable(String bucketId, WeIdPrivateKey privateKey) {
        try {
            TransactionReceipt receipt = getDataBucket(privateKey).enable(
                bucketId);
            if (StringUtils
                .equals(receipt.getStatus(), ParamKeyConstant.TRNSACTION_RECEIPT_STATUS_SUCCESS)) {
                logger.info("[enable] enable Bucket success, bucketId is {}.", bucketId);
                ErrorCode  code = analysisErrorCode(receipt, DataBucket.FUNC_ENABLE);
                return new ResponseData<Boolean>(code == ErrorCode.SUCCESS, code);
            }
            logger.error("[enable] enable Bucket fail, bucketId is {}.", bucketId);
            return new ResponseData<Boolean>(false, ErrorCode.TRANSACTION_EXECUTE_ERROR);
        } catch (Exception e) {
            logger.error("[enable] enable Bucket has excpetion, bucketId is {}, exception:",
                bucketId, e);
            return new ResponseData<Boolean>(false, ErrorCode.UNKNOW_ERROR);
        }
    }

    @Override
    public ResponseData<Boolean> disable(String bucketId, WeIdPrivateKey privateKey) {
        try {
            TransactionReceipt receipt = getDataBucket(privateKey).disable(
                bucketId);
            if (StringUtils
                .equals(receipt.getStatus(), ParamKeyConstant.TRNSACTION_RECEIPT_STATUS_SUCCESS)) {
                logger.info("[disable] disable Bucket success, bucketId is {}.", bucketId);
                ErrorCode  code = analysisErrorCode(receipt, DataBucket.FUNC_DISABLE);
                return new ResponseData<Boolean>(code == ErrorCode.SUCCESS, code);
            }
            logger.error("[disable] disable Bucket fail, bucketId is {}.", bucketId);
            return new ResponseData<Boolean>(false, ErrorCode.TRANSACTION_EXECUTE_ERROR);
        } catch (Exception e) {
            logger.error("[disable] disable Bucket has excpetion, bucketId is {}, exception:", 
                bucketId, e);
            return new ResponseData<Boolean>(false, ErrorCode.UNKNOW_ERROR);
        }
    }

    @Override
    public ResponseData<List<HashContract>> getAllBucket() {
        int startIndex = 0;
        BigInteger num = BigInteger.valueOf(10);
        List<HashContract>  hashContractList = new ArrayList<HashContract>();
        try {
            while (true) {
                BigInteger offset = BigInteger.valueOf(startIndex);
                Tuple4<List<String>, List<String>, List<BigInteger>, BigInteger> data = 
                    dataBucket.getAllBucket(offset, num);
                List<String> bucketIdList = data.getValue1();
                List<String> ownerList = data.getValue2();
                List<BigInteger> timesList = data.getValue3();
                BigInteger next = data.getValue4();
                for (int i = 0; i < bucketIdList.size(); i++) {
                    if (WeIdUtils.isEmptyStringAddress(ownerList.get(i))) {
                        break;
                    }
                    HashContract hash = new HashContract();
                    hash.setHash(bucketIdList.get(i));
                    hash.setOwner(ownerList.get(i));
                    hash.setTime(timesList.get(i).longValue());
                    hashContractList.add(hash);
                }
                if (next.intValue() == 0) {
                    break;
                }
                startIndex = next.intValue();
            }
            logger.info("[getAllBucket] get the all Bucket success.");
            return new ResponseData<List<HashContract>>(hashContractList, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("[getAllBucket] get the all Bucket fail.", e);
            return new ResponseData<List<HashContract>>(hashContractList, ErrorCode.UNKNOW_ERROR);
        }
    }
    
    @Override
    public ResponseData<Boolean> updateBucketOwner(
        String bucketId, 
        String newOwner, 
        WeIdPrivateKey privateKey
    ) {
        try {
            TransactionReceipt receipt = getDataBucket(privateKey)
                .updateBucketOwner(bucketId, newOwner);
            if (StringUtils
                .equals(receipt.getStatus(), ParamKeyConstant.TRNSACTION_RECEIPT_STATUS_SUCCESS)) {
                logger.info("[updateBucketOwner] update owner success, bucketId is {}.", bucketId);
                ErrorCode  code = analysisErrorCode(receipt, DataBucket.FUNC_UPDATEBUCKETOWNER);
                return new ResponseData<Boolean>(code == ErrorCode.SUCCESS, code);
            }
            logger.error("[updateBucketOwner] update owner fail, bucketId is {}.", bucketId);
            return new ResponseData<Boolean>(false, ErrorCode.TRANSACTION_EXECUTE_ERROR);
        } catch (Exception e) {
            logger.error(
                "[updateBucketOwner] update owner has excpetion, bucketId is {}, exception:", 
                bucketId, e);
            return new ResponseData<Boolean>(false, ErrorCode.UNKNOW_ERROR);
        }
    }

    @Override
    public ResponseData<List<String>> getActivatedUserList(String bucketId) {
        int startIndex = 0;
        BigInteger num = BigInteger.valueOf(10);
        List<String> userList = new ArrayList<String>();
        try {
            while (true) {
                BigInteger index = BigInteger.valueOf(startIndex);
                Tuple2<List<String>, BigInteger> data = 
                    dataBucket.getActivatedUserList(bucketId, index, num);
                List<String> useList = data.getValue1();
                BigInteger next = data.getValue2();
                for (int i = 0; i < useList.size(); i++) {
                    if (WeIdUtils.isEmptyStringAddress(useList.get(i))) {
                        break;
                    }
                    userList.add(useList.get(i));
                }
                if (next.intValue() == 0) {
                    break;
                }
                startIndex = next.intValue();
            }
            logger.info("[getActivatedUserList] get the use list by bucketId success.");
            return new ResponseData<List<String>>(userList, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("[getActivatedUserList] get the use list by bucketId fail.", e);
            return new ResponseData<List<String>>(userList, ErrorCode.UNKNOW_ERROR);
        }
    }
}
