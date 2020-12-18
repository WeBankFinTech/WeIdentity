package com.webank.weid.contract.deploy.v2;

import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.contract.precompiled.cns.CnsInfo;
import org.fisco.bcos.sdk.contract.precompiled.cns.CnsService;
import org.fisco.bcos.sdk.crypto.keypair.CryptoKeyPair;
import org.fisco.bcos.sdk.model.RetCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.CnsType;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.contract.v2.DataBucket;
import com.webank.weid.exception.WeIdBaseException;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.service.BaseService;
import com.webank.weid.service.impl.engine.DataBucketServiceEngine;
import com.webank.weid.service.impl.engine.fiscov2.DataBucketServiceEngineV2;
import com.webank.weid.suite.api.crypto.params.KeyGenerator;

public class RegisterAddressV2 {

    /**
     * log4j.
     */
    private static final Logger logger = LoggerFactory.getLogger(RegisterAddressV2.class);

    private static CryptoKeyPair cryptoKeyPair;

    private static CryptoKeyPair getCryptoKeyPair(WeIdPrivateKey inputPrivateKey) {
        if (cryptoKeyPair == null) {
            cryptoKeyPair = KeyGenerator.createKeyPair(inputPrivateKey);
        }
        return cryptoKeyPair;
    }

    private static DataBucketServiceEngine getBucket(CnsType cnsType) {
        return new DataBucketServiceEngineV2(cnsType);
    }

    /**
     * 根据hash，合约地址，key进行地址注册到cns中.
     * @param cnsType 地址注册到的目标cns类型
     * @param hash 合约地址的hash值
     * @param address 合约地址
     * @param key 合约地址的key
     * @param privateKey 私钥信息
     */
    public static void registerAddress(
        CnsType cnsType,
        String hash, 
        String address, 
        String key, 
        WeIdPrivateKey privateKey
    ) {
        logger.info("[registerAddress] begin register key = {}, value = {}.", key, address);
        if (StringUtils.isBlank(address)) {
            logger.error("[registerAddress] can not find the address.");
            throw new WeIdBaseException("register address fail.");
        }
        ResponseData<Boolean> result = getBucket(cnsType).put(hash, key, address, privateKey);
        if (!result.getResult()) {
            logger.error("[registerAddress] register address fail, please check the log.");
            throw new WeIdBaseException(ErrorCode.getTypeByErrorCode(result.getErrorCode()));
        }
        logger.info("[registerAddress] register address successfully.");
    }

    /**
     * 注册全局bucket地址.
     * @param cnsType 需要注册的cns类型
     * @param weIdPrivateKey 私钥信息
     * @throws WeIdBaseException 注册过程中的异常
     */
    public static void registerBucketToCns(
        CnsType cnsType, 
        WeIdPrivateKey weIdPrivateKey
    ) throws WeIdBaseException {
        logger.info(
            "[registerBucketToCns] begin register bucket to CNS, type = {}.", 
            cnsType.getName()
        );
        CnsInfo cnsInfo = BaseService.getBucketByCns(cnsType);
        //如果地址是为空则说明是首次注册
        if (cnsInfo != null && StringUtils.isNotBlank(cnsInfo.getAddress())) {
            logger.info("[registerBucketToCns] the bucket is registed, it is no need to regist.");
            return;
        }
        try {
            //先进行地址部署
            String bucketAddr = deployBucket(weIdPrivateKey);
            RetCode retCode = 
                new CnsService(BaseService.getClient(), getCryptoKeyPair(weIdPrivateKey))
                .registerCNS(cnsType.getName(), cnsType.getVersion(), bucketAddr, DataBucket.ABI);
            if (retCode.getCode() != 1) {
                throw new WeIdBaseException(retCode.getCode() + "-" + retCode.getMessage());
            }
            logger.info("[registerBucketToCns] the bucket register successfully.");
        } catch (WeIdBaseException e) {
            logger.error("[registerBucketToCns] the bucket register fail,{}.", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("[registerBucketToCns] register bucket has error.", e);
            throw new WeIdBaseException("register bucket has error.", e);
        }
    }
    
    private static String deployBucket(WeIdPrivateKey privateKey) throws Exception {
        logger.info("[deployBucket] begin deploy bucket.");
        //先进行地址部署
        DataBucket dataBucket = DataBucket.deploy(
            BaseService.getClient(),
            getCryptoKeyPair(privateKey)
        );
        return dataBucket.getContractAddress();
    }
    
    /**
     * 链上启用CNS.
     * @param cnsType cns类型
     * @param hash hash值
     * @param weIdPrivateKey hash所属私钥
     * @return 返回是否启用成功
     */
    public static boolean enableHash(CnsType cnsType, String hash, WeIdPrivateKey weIdPrivateKey) {
        logger.info("[enableHash] enable hash on chain.");
        boolean result = getBucket(cnsType).enable(hash, weIdPrivateKey).getResult();
        logger.info("[enableHash] the result of enable. result = {}", result);
        return result;
    }
    
    /**
     * 注册所有的databucket到cns中.
     * @param privateKey 部署DataBucket私钥
     */
    public static void registerAllCns(WeIdPrivateKey privateKey) {
        for (CnsType cnsType : CnsType.values()) {
            // 注册cns
            RegisterAddressV2.registerBucketToCns(cnsType, privateKey);
        }
    }
    
    /**
     * 将数据注册到机构配置CNS中
     * @param module 存储模块
     * @param key 存放的key
     * @param value 存放的值
     * @param privateKey 私钥
     */
    public static void registerHashToOrgConfig(
        String module, 
        String key, 
        String value, 
        WeIdPrivateKey privateKey
    ) {
        // 默认将主合约hash注册到机构配置cns中
        RegisterAddressV2.registerAddress(
            CnsType.ORG_CONFING,
            module, 
            value, 
            key, 
            privateKey
        );
    }
}
