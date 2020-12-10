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

package com.webank.weid.service.impl;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import com.webank.wedpr.selectivedisclosure.CredentialTemplateEntity;
import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.crypto.signature.ECDSASignatureResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.protocol.base.Cpt;
import com.webank.weid.protocol.base.CptBaseInfo;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.request.CptMapArgs;
import com.webank.weid.protocol.request.CptStringArgs;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.protocol.response.RsvSignature;
import com.webank.weid.rpc.CptService;
import com.webank.weid.suite.cache.CacheManager;
import com.webank.weid.suite.cache.CacheNode;
import com.webank.weid.util.DataToolUtils;
import com.webank.weid.util.WeIdUtils;

/**
 * Service implementation for operation on CPT (Claim Protocol Type).
 *
 * @author lingfenghe
 */
public class CptServiceImpl extends AbstractService implements CptService {

    private static final Logger logger = LoggerFactory.getLogger(CptServiceImpl.class);
    //获取CPT缓存节点
    private static CacheNode<ResponseData<Cpt>> cptCahceNode =
        CacheManager.registerCacheNode("SYS_CPT", 1000 * 3600 * 24L);

    /**
     * Register a new CPT with a pre-set CPT ID, to the blockchain.
     *
     * @param args the args
     * @param cptId the CPT ID
     * @return response data
     */
    public ResponseData<CptBaseInfo> registerCpt(CptStringArgs args, Integer cptId) {
        if (args == null || cptId == null || cptId <= 0) {
            logger.error(
                "[registerCpt1] input argument is illegal");
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        try {
            CptMapArgs cptMapArgs = new CptMapArgs();
            cptMapArgs.setWeIdAuthentication(args.getWeIdAuthentication());
            Map<String, Object> cptJsonSchemaMap =
                DataToolUtils.deserialize(args.getCptJsonSchema(), HashMap.class);
            cptMapArgs.setCptJsonSchema(cptJsonSchemaMap);
            return this.registerCpt(cptMapArgs, cptId);
        } catch (Exception e) {
            logger.error("[registerCpt1] register cpt failed due to unknown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }


    /**
     * This is used to register a new CPT to the blockchain.
     *
     * @param args the args
     * @return the response data
     */
    public ResponseData<CptBaseInfo> registerCpt(CptStringArgs args) {

        try {
            if (args == null) {
                logger.error(
                    "[registerCpt1]input CptStringArgs is null");
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }

            CptMapArgs cptMapArgs = new CptMapArgs();
            cptMapArgs.setWeIdAuthentication(args.getWeIdAuthentication());
            Map<String, Object> cptJsonSchemaMap =
                DataToolUtils.deserialize(args.getCptJsonSchema(), HashMap.class);
            cptMapArgs.setCptJsonSchema(cptJsonSchemaMap);
            return this.registerCpt(cptMapArgs);
        } catch (Exception e) {
            logger.error("[registerCpt1] register cpt failed due to unknown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * Register a new CPT with a pre-set CPT ID, to the blockchain.
     *
     * @param args the args
     * @param cptId the CPT ID
     * @return response data
     */
    public ResponseData<CptBaseInfo> registerCpt(CptMapArgs args, Integer cptId) {
        if (args == null || cptId == null || cptId <= 0) {
            logger.error("[registerCpt] input argument is illegal");
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        try {
            ErrorCode errorCode =
                this.validateCptArgs(
                    args.getWeIdAuthentication(),
                    args.getCptJsonSchema()
                );
            if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
                return new ResponseData<>(null, errorCode);
            }

            String weId = args.getWeIdAuthentication().getWeId();
            WeIdPrivateKey weIdPrivateKey = args.getWeIdAuthentication().getWeIdPrivateKey();
            String cptJsonSchemaNew = DataToolUtils.cptSchemaToString(args);
            RsvSignature rsvSignature = sign(
                weId,
                cptJsonSchemaNew,
                weIdPrivateKey);
            String address = WeIdUtils.convertWeIdToAddress(weId);
            return cptServiceEngine.registerCpt(cptId, address, cptJsonSchemaNew, rsvSignature,
                weIdPrivateKey.getPrivateKey(), WeIdConstant.CPT_DATA_INDEX);
        } catch (Exception e) {
            logger.error("[registerCpt] register cpt failed due to unknown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * This is used to register a new CPT to the blockchain.
     *
     * @param args the args
     * @return the response data
     */
    public ResponseData<CptBaseInfo> registerCpt(CptMapArgs args) {

        try {
            if (args == null) {
                logger.error("[registerCpt]input CptMapArgs is null");
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }
            ErrorCode validateResult =
                this.validateCptArgs(
                    args.getWeIdAuthentication(),
                    args.getCptJsonSchema()
                );

            if (validateResult.getCode() != ErrorCode.SUCCESS.getCode()) {
                return new ResponseData<>(null, validateResult);
            }

            String weId = args.getWeIdAuthentication().getWeId();
            WeIdPrivateKey weIdPrivateKey = args.getWeIdAuthentication().getWeIdPrivateKey();
            String cptJsonSchemaNew = DataToolUtils.cptSchemaToString(args);
            RsvSignature rsvSignature = sign(
                weId,
                cptJsonSchemaNew,
                weIdPrivateKey);
            String address = WeIdUtils.convertWeIdToAddress(weId);
            return cptServiceEngine.registerCpt(address, cptJsonSchemaNew, rsvSignature,
                weIdPrivateKey.getPrivateKey(), WeIdConstant.CPT_DATA_INDEX);
        } catch (Exception e) {
            logger.error("[registerCpt] register cpt failed due to unknown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * this is used to query cpt with the latest version which has been registered.
     *
     * @param cptId the cpt id
     * @return the response data
     */
    public ResponseData<Cpt> queryCpt(Integer cptId) {

        try {
            if (cptId == null || cptId < 0) {
                return new ResponseData<>(null, ErrorCode.CPT_ID_ILLEGAL);
            }
            String cptIdStr = String.valueOf(cptId);
            ResponseData<Cpt> result = cptCahceNode.get(cptIdStr);
            if (result == null) {
                result = cptServiceEngine.queryCpt(cptId, WeIdConstant.CPT_DATA_INDEX);
                if (result.getErrorCode().intValue() == ErrorCode.SUCCESS.getCode()) {
                    cptCahceNode.put(cptIdStr, result);
                }
            }
            return result;
        } catch (Exception e) {
            logger.error("[updateCpt] query cpt failed due to unknown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * This is used to update a CPT data which has been register.
     *
     * @param args the args
     * @return the response data
     */
    public ResponseData<CptBaseInfo> updateCpt(CptStringArgs args, Integer cptId) {

        try {
            if (args == null) {
                logger.error("[updateCpt1]input UpdateCptArgs is null");
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }

            CptMapArgs cptMapArgs = new CptMapArgs();
            cptMapArgs.setWeIdAuthentication(args.getWeIdAuthentication());
            cptMapArgs.setCptJsonSchema(
                DataToolUtils.deserialize(args.getCptJsonSchema(), HashMap.class));
            return this.updateCpt(cptMapArgs, cptId);
        } catch (Exception e) {
            logger.error("[updateCpt1] update cpt failed due to unkown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * This is used to update a CPT data which has been register.
     *
     * @param args the args
     * @return the response data
     */
    public ResponseData<CptBaseInfo> updateCpt(CptMapArgs args, Integer cptId) {

        try {
            if (args == null) {
                logger.error("[updateCpt]input UpdateCptArgs is null");
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }
            if (cptId == null || cptId.intValue() < 0) {
                logger.error("[updateCpt]input cptId illegal");
                return new ResponseData<>(null, ErrorCode.CPT_ID_ILLEGAL);
            }
            ErrorCode errorCode =
                this.validateCptArgs(
                    args.getWeIdAuthentication(),
                    args.getCptJsonSchema()
                );

            if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
                return new ResponseData<>(null, errorCode);
            }

            String weId = args.getWeIdAuthentication().getWeId();
            WeIdPrivateKey weIdPrivateKey = args.getWeIdAuthentication().getWeIdPrivateKey();
            String cptJsonSchemaNew = DataToolUtils.cptSchemaToString(args);
            RsvSignature rsvSignature = sign(
                weId,
                cptJsonSchemaNew,
                weIdPrivateKey);
            String address = WeIdUtils.convertWeIdToAddress(weId);
            ResponseData<CptBaseInfo> result = cptServiceEngine.updateCpt(
                cptId,
                address,
                cptJsonSchemaNew,
                rsvSignature,
                weIdPrivateKey.getPrivateKey(),
                WeIdConstant.CPT_DATA_INDEX);
            if (result.getErrorCode().intValue() == ErrorCode.SUCCESS.getCode()) {
                cptCahceNode.remove(String.valueOf(cptId));
            }
            return result;
        } catch (Exception e) {
            logger.error("[updateCpt] update cpt failed due to unkown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }


    private RsvSignature sign(
        String cptPublisher,
        String jsonSchema,
        WeIdPrivateKey cptPublisherPrivateKey) {

        StringBuilder sb = new StringBuilder();
        sb.append(cptPublisher);
        sb.append(WeIdConstant.PIPELINE);
        sb.append(jsonSchema);
        ECDSASignatureResult signatureData = DataToolUtils.secp256k1SignToSignature(
            sb.toString(), new BigInteger(cptPublisherPrivateKey.getPrivateKey()));
        return DataToolUtils.convertSignatureDataToRsv(signatureData);
    }

    private ErrorCode validateCptArgs(
        WeIdAuthentication weIdAuthentication,
        Map<String, Object> cptJsonSchemaMap) throws Exception {

        if (weIdAuthentication == null) {
            logger.error("Input cpt weIdAuthentication is invalid.");
            return ErrorCode.WEID_AUTHORITY_INVALID;
        }

        String weId = weIdAuthentication.getWeId();
        if (!WeIdUtils.isWeIdValid(weId)) {
            logger.error("Input cpt publisher : {} is invalid.", weId);
            return ErrorCode.WEID_INVALID;
        }

        ErrorCode errorCode = validateCptJsonSchemaMap(cptJsonSchemaMap);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return errorCode;
        }
        String cptJsonSchema = DataToolUtils.serialize(cptJsonSchemaMap);
        if (!DataToolUtils.isCptJsonSchemaValid(cptJsonSchema)) {
            logger.error("Input cpt json schema : {} is invalid.", cptJsonSchemaMap);
            return ErrorCode.CPT_JSON_SCHEMA_INVALID;
        }
        WeIdPrivateKey weIdPrivateKey = weIdAuthentication.getWeIdPrivateKey();
        if (weIdPrivateKey == null
            || StringUtils.isEmpty(weIdPrivateKey.getPrivateKey())) {
            logger.error(
                "Input cpt publisher private key : {} is in valid.",
                weIdPrivateKey
            );
            return ErrorCode.WEID_PRIVATEKEY_INVALID;
        }

        if (!WeIdUtils.validatePrivateKeyWeIdMatches(weIdPrivateKey, weId)) {
            return ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode validateCptJsonSchemaMap(
        Map<String, Object> cptJsonSchemaMap) throws Exception {
        if (cptJsonSchemaMap == null || cptJsonSchemaMap.isEmpty()) {
            logger.error("Input cpt json schema is invalid.");
            return ErrorCode.CPT_JSON_SCHEMA_INVALID;
        }
        //String cptJsonSchema = JsonUtil.objToJsonStr(cptJsonSchemaMap);
        String cptJsonSchema = DataToolUtils.serialize(cptJsonSchemaMap);
        if (!DataToolUtils.isCptJsonSchemaValid(cptJsonSchema)) {
            logger.error("Input cpt json schema : {} is invalid.", cptJsonSchemaMap);
            return ErrorCode.CPT_JSON_SCHEMA_INVALID;
        }
        return ErrorCode.SUCCESS;
    }



    /* (non-Javadoc)
     * @see com.webank.weid.rpc.CptService#queryCredentialTemplate(java.lang.Integer)
     */
    @Override
    public ResponseData<CredentialTemplateEntity> queryCredentialTemplate(Integer cptId) {

        return cptServiceEngine.queryCredentialTemplate(cptId);
    }
}
