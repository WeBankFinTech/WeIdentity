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

package com.webank.weid.suite.encode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.DataDriverConstant;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.ParamKeyConstant;
import com.webank.weid.exception.DataTypeCastException;
import com.webank.weid.exception.EncodeSuiteException;
import com.webank.weid.protocol.amop.GetEncryptKeyArgs;
import com.webank.weid.protocol.response.GetEncryptKeyResponse;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.rpc.AmopService;
import com.webank.weid.service.BaseService;
import com.webank.weid.service.impl.AmopServiceImpl;
import com.webank.weid.suite.api.crypto.CryptoServiceFactory;
import com.webank.weid.suite.api.crypto.params.CryptoType;
import com.webank.weid.suite.api.crypto.params.KeyGenerator;
import com.webank.weid.suite.api.persistence.PersistenceFactory;
import com.webank.weid.suite.api.persistence.inf.Persistence;
import com.webank.weid.suite.api.persistence.params.PersistenceType;
import com.webank.weid.suite.entity.EncodeData;
import com.webank.weid.util.DataToolUtils;
import com.webank.weid.util.PropertyUtils;

/**
 * 密文编解码处理器.
 *
 * @author v_wbgyang
 */
public class CipherEncodeProcessor extends BaseService implements EncodeProcessor {

    private static final Logger logger = LoggerFactory.getLogger(CipherEncodeProcessor.class);

    private Persistence dataDriver;

    private PersistenceType persistenceType;

    protected AmopService amopService = new AmopServiceImpl();

    private Persistence getDataDriver() {
        String type = PropertyUtils.getProperty("persistence_type");
        if (type.equals("mysql")) {
            persistenceType = PersistenceType.Mysql;
        } else if (type.equals("redis")) {
            persistenceType = PersistenceType.Redis;
        }
        if (dataDriver == null) {
            dataDriver = PersistenceFactory.build(persistenceType);
        }
        return dataDriver;
    }

    /**
     * 密文编码处理：先进行压缩，然后进行AES加密.
     */
    @Override
    public String encode(EncodeData encodeData) throws EncodeSuiteException {
        logger.info("[encode] cipher encode process, encryption with AES.");
        try {
            String key = KeyGenerator.getKey();
            Map<String, Object> keyMap = new HashMap<String, Object>();
            keyMap.put(ParamKeyConstant.KEY_DATA, key);
            keyMap.put(ParamKeyConstant.KEY_VERIFIERS, encodeData.getVerifiers());
            String saveData = DataToolUtils.serialize(keyMap);

            //将数据进行AES加密处理
            String value =
                CryptoServiceFactory
                    .getCryptoService(CryptoType.AES)
                    .encrypt(encodeData.getData(), key);

            //保存秘钥
            ResponseData<Integer> response = this.getDataDriver().add(
                DataDriverConstant.DOMAIN_ENCRYPTKEY, encodeData.getId(), saveData);
            if (response.getErrorCode().intValue() != ErrorCode.SUCCESS.getCode()) {
                throw new EncodeSuiteException(
                    ErrorCode.getTypeByErrorCode(response.getErrorCode().intValue())
                );
            }
            logger.info("[encode] cipher encode process finished.");
            return value;
        } catch (EncodeSuiteException e) {
            logger.error("[encode] encode processor has some error.", e);
            throw e;
        } catch (Exception e) {
            logger.error("[encode] encode processor has unknow error.", e);
            throw new EncodeSuiteException(e);
        }
    }

    /**
     * 密文解码处理：先进行AES解密， 然后进行解压.
     */
    @Override
    public String decode(EncodeData encodeData) throws EncodeSuiteException {
        logger.info("[decode] cipher decode process, decryption with AES.");
        try {
            String key = this.getEntryptKey(encodeData);
            //将数据进行AES解密
            String value =
                CryptoServiceFactory
                    .getCryptoService(CryptoType.AES)
                    .decrypt(encodeData.getData(), key);
            //数据进行解压
            logger.info("[decode] cipher decode process finished.");
            return value;
        } catch (EncodeSuiteException e) {
            logger.error("[decode] decode processor has some error.", e);
            throw e;
        } catch (Exception e) {
            logger.error("[decode] decode processor has unknow error.", e);
            throw new EncodeSuiteException(e);
        }
    }

    /**
     * 获取秘钥.
     *
     * @param encodeData 编解码实体
     * @return return the key
     */
    private String getEntryptKey(EncodeData encodeData) {
        //说明是当前机构，这个时候不适用于AMOP获取key，而是从本地数据库中获取key
        if (fiscoConfig.getAmopId().equals(encodeData.getAmopId())) {
            logger.info("get Encrypt Key from DB.");
            //保存秘钥
            ResponseData<String> response =
                this.getDataDriver().get(DataDriverConstant.DOMAIN_ENCRYPTKEY, encodeData.getId());
            if (response.getErrorCode().intValue() != ErrorCode.SUCCESS.getCode()) {
                throw new EncodeSuiteException(
                    ErrorCode.getTypeByErrorCode(response.getErrorCode().intValue())
                );
            }
            return this.getEncryptKey(encodeData, response.getResult());
        } else {
            logger.info("get Encrypt Key By AMOP.");
            //获取秘钥，
            return this.requestEncryptKeyByAmop(encodeData);
        }
    }

    /**
     * 本机构取秘钥(需要判断权限控制).
     *
     * @param encodeData 编解码实体
     * @param value 数据库中存储的秘钥结构数据
     * @return 返回秘钥
     */
    private String getEncryptKey(EncodeData encodeData, String value) {
        if (encodeData.getWeIdAuthentication() == null) {
            logger.info("[getEncryptKey] the weid Authentication is null.");
            throw new EncodeSuiteException(ErrorCode.ENCRYPT_KEY_NO_PERMISSION);
        }
        try {
            Map<String, Object> keyMap = DataToolUtils.deserialize(
                value,
                new HashMap<String, Object>().getClass()
            );
            String weId = encodeData.getWeIdAuthentication().getWeId();
            List<String> verifiers = (ArrayList<String>) keyMap.get(ParamKeyConstant.KEY_VERIFIERS);
            // 如果verifiers为empty,或者传入的weId为空，或者weId不在指定列表中，则无权限获取秘钥数据
            if (CollectionUtils.isEmpty(verifiers)
                || StringUtils.isBlank(weId)
                || !verifiers.contains(weId)) {
                logger.error("[getEncryptKey] no access to get the data, this weid is {}.", weId);
                throw new EncodeSuiteException(ErrorCode.ENCRYPT_KEY_NO_PERMISSION);
            }
            return (String) keyMap.get(ParamKeyConstant.KEY_DATA);
        } catch (DataTypeCastException e) {
            logger.error("[getEncryptKey] deserialize the data error, you should upgrade SDK.", e);
            throw new EncodeSuiteException(ErrorCode.ENCRYPT_KEY_INVALID);
        }
    }

    /**
     * 通过AMOP获取秘钥.
     *
     * @param encodeData 编解码实体
     * @return 返回秘钥
     */
    private String requestEncryptKeyByAmop(EncodeData encodeData) {
        GetEncryptKeyArgs args = new GetEncryptKeyArgs();
        args.setKeyId(encodeData.getId());
        args.setMessageId(DataToolUtils.getUuId32());
        args.setToAmopId(encodeData.getAmopId());
        args.setFromAmopId(fiscoConfig.getAmopId());
        if (encodeData.getWeIdAuthentication() != null) {
            String signValue = DataToolUtils.secp256k1Sign(
                encodeData.getId(),
                encodeData.getWeIdAuthentication().getWeIdPrivateKey()
            );
            args.setSignValue(signValue);
            args.setWeId(encodeData.getWeIdAuthentication().getWeId());
        }
        ResponseData<GetEncryptKeyResponse> resResponse =
            amopService.getEncryptKey(encodeData.getAmopId(), args);
        if (resResponse.getErrorCode().intValue() != ErrorCode.SUCCESS.getCode()) {
            logger.error(
                "[requestEncryptKeyByAmop] AMOP response fail, dataId={}, "
                    + "errorCode={}, errorMessage={}",
                encodeData.getId(),
                resResponse.getErrorCode(),
                resResponse.getErrorMessage()
            );
            throw new EncodeSuiteException(
                ErrorCode.getTypeByErrorCode(resResponse.getErrorCode().intValue())
            );
        }
        GetEncryptKeyResponse keyResponse = resResponse.getResult();
        ErrorCode errorCode =
            ErrorCode.getTypeByErrorCode(keyResponse.getErrorCode().intValue());
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            logger.error(
                "[requestEncryptKeyByAmop] requestEncryptKey error, dataId={},"
                    + " errorCode={}, errorMessage={}",
                encodeData.getId(),
                keyResponse.getErrorCode(),
                keyResponse.getErrorMessage()
            );
            throw new EncodeSuiteException(errorCode);
        }
        return keyResponse.getEncryptKey();
    }
}
