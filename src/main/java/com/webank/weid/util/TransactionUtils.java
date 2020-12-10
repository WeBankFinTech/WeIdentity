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

package com.webank.weid.util;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.abi.datatypes.Address;
import org.fisco.bcos.sdk.abi.datatypes.DynamicBytes;
import org.fisco.bcos.sdk.abi.datatypes.StaticArray;
import org.fisco.bcos.sdk.abi.datatypes.Type;
import org.fisco.bcos.sdk.abi.datatypes.generated.Bytes32;
import org.fisco.bcos.sdk.abi.datatypes.generated.Int256;
import org.fisco.bcos.sdk.abi.datatypes.generated.Uint256;
import org.fisco.bcos.sdk.model.TransactionReceipt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.JsonSchemaConstant;
import com.webank.weid.constant.ParamKeyConstant;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.protocol.base.CptBaseInfo;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.protocol.response.RsvSignature;
import com.webank.weid.protocol.response.TransactionInfo;

/**
 * Transaction related utility functions. This class handles specific Transaction tasks, including
 * sending raw transactions into blockchain, and parse the transaction receipts.
 *
 * @author chaoxinhu 2019.3
 */

public class TransactionUtils {

    private static final Logger logger = LoggerFactory.getLogger(TransactionUtils.class);

    /**
     * Check validity and build input params for createWeId (with attributes - public key) function.
     * Used by Restful API service.
     *
     * @param inputParam the input param json
     * @return the StaticArray
     * @throws Exception IOException
     */
    public static ResponseData<List<Type>> buildCreateWeIdInputParameters(String inputParam)
        throws Exception {

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode inputParamNode = objectMapper.readTree(inputParam);
        JsonNode publicKeyNode = inputParamNode.get(ParamKeyConstant.PUBLIC_KEY);
        if (publicKeyNode == null) {
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        String publicKey = publicKeyNode.textValue();
        if (StringUtils.isEmpty(publicKey)) {
            logger.error("[createWeId]: input parameter publickey is null.");
            return new ResponseData<>(null, ErrorCode.WEID_PUBLICKEY_INVALID);
        }
        String weId = WeIdUtils.convertPublicKeyToWeId(publicKey);
        String addr = WeIdUtils.convertWeIdToAddress(weId);
        if (!WeIdUtils.isValidAddress(addr)) {
            logger.error("[createWeId]: input parameter publickey is invalid.");
            return new ResponseData<>(null, ErrorCode.WEID_PUBLICKEY_INVALID);
        }
        // We do not check DID existence in this case since it does not really affect the outcome.
        List<Type> result = Arrays.<Type>asList(
            new Address(addr),
            DataToolUtils.stringToBytes32(WeIdConstant.WEID_DOC_CREATED),
            DataToolUtils.stringToDynamicBytes(DateUtils.getNoMillisecondTimeStampString()),
            DateUtils.getNoMillisecondTimeStampInt256()
        );
        return new ResponseData<>(result, ErrorCode.SUCCESS);
    }

    /**
     * Check validity and build input params for registerAuthorityIssuer function. Used by Restful
     * API service.
     *
     * @param inputParam the input Param json
     * @return the StaticArray
     * @throws Exception IOException
     */
    public static ResponseData<List<Type>> buildAuthorityIssuerInputParameters(String inputParam)
        throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode inputParamNode = objectMapper.readTree(inputParam);
        JsonNode weIdNode = inputParamNode.get(ParamKeyConstant.WEID);
        JsonNode nameNode = inputParamNode.get(ParamKeyConstant.AUTHORITY_ISSUER_NAME);
        if (weIdNode == null || nameNode == null) {
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        String weId = weIdNode.textValue();
        if (!WeIdUtils.isWeIdValid(weId)) {
            return new ResponseData<>(null, ErrorCode.WEID_DOES_NOT_EXIST);
        }

        String name = nameNode.textValue();
        if (StringUtils.isEmpty(name)
            || name.length() > WeIdConstant.MAX_AUTHORITY_ISSUER_NAME_LENGTH) {
            logger.error("Input cpt publisher : {} is invalid.", name);
            return new ResponseData<>(null, ErrorCode.AUTHORITY_ISSUER_NAME_ILLEGAL);
        }
        List<Type> result = Arrays.<Type>asList(
            new Address(WeIdUtils.convertWeIdToAddress(weId)),
            getParamName(name),
            getParamCreated(WeIdConstant.AUTHORITY_ISSUER_ARRAY_LEGNTH),
            getDefaultAccValue());
        return new ResponseData<>(result, ErrorCode.SUCCESS);
    }

    /**
     * Convert the authority issuer org name into the static array.
     *
     * @param name authorityIssuer name
     * @return the StaticArray
     */
    private static StaticArray<Bytes32> getParamName(String name) {
        String[] nameArray = new String[WeIdConstant.AUTHORITY_ISSUER_ARRAY_LEGNTH];
        nameArray[0] = name;
        return DataToolUtils.stringArrayToBytes32StaticArray(nameArray);
    }

    /**
     * Get the default accumulator value.
     *
     * @return the StaticArray
     */
    private static DynamicBytes getDefaultAccValue() {
        String defaultAccValue = WeIdConstant.DEFAULT_ACCUMULATOR_VALUE;
        DynamicBytes accValue = new DynamicBytes(defaultAccValue
            .getBytes(StandardCharsets.UTF_8)
        );
        return accValue;
    }

    /**
     * Check validity and build input params for registerCpt blockchain function. Used by Restful
     * API service.
     *
     * @param inputParam the input Param json
     * @return the StaticArray
     * @throws Exception IOException
     */
    public static ResponseData<List<Type>> buildRegisterCptInputParameters(String inputParam)
        throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode inputParamNode = objectMapper.readTree(inputParam);
        JsonNode weIdNode = inputParamNode.get(ParamKeyConstant.WEID);
        JsonNode cptJsonSchemaNode = inputParamNode.get(ParamKeyConstant.CPT_JSON_SCHEMA);
        JsonNode cptSignatureNode = inputParamNode.get(ParamKeyConstant.CPT_SIGNATURE);
        if (weIdNode == null || cptJsonSchemaNode == null || cptSignatureNode == null) {
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }

        String weId = weIdNode.textValue();
        if (!WeIdUtils.isWeIdValid(weId)) {
            return new ResponseData<>(null, ErrorCode.WEID_DOES_NOT_EXIST);
        }

        String cptJsonSchema = cptJsonSchemaNode.toString();
        String cptJsonSchemaNew = complementCptJsonSchema(cptJsonSchema);
        Map<String, Object> cptJsonSchemaMap = DataToolUtils.deserialize(
            cptJsonSchemaNew,
            HashMap.class
        );
        if (StringUtils.isEmpty(cptJsonSchemaNew)
            || !DataToolUtils.isCptJsonSchemaValid(cptJsonSchemaNew)) {
            logger.error("Input cpt json schema : {} is invalid.", cptJsonSchemaNew);
            return new ResponseData<>(null, ErrorCode.CPT_JSON_SCHEMA_INVALID);
        }

        String cptSignature = cptSignatureNode.textValue();
        if (!DataToolUtils.isValidBase64String(cptSignature)) {
            logger.error("Input cpt signature invalid: {}", cptSignature);
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        RsvSignature rsvSignature =
            DataToolUtils.convertSignatureDataToRsv(
                DataToolUtils.convertBase64StringToSignatureData(cptSignature)
            );

        StaticArray<Bytes32> bytes32Array = DataToolUtils.stringArrayToBytes32StaticArray(
            new String[WeIdConstant.CPT_STRING_ARRAY_LENGTH]
        );
        List<Type> result = Arrays.<Type>asList(
            new Address(WeIdUtils.convertWeIdToAddress(weId)),
            getParamCreated(WeIdConstant.CPT_LONG_ARRAY_LENGTH),
            bytes32Array,
            getParamJsonSchema(cptJsonSchemaNew),
            rsvSignature.getV(),
            rsvSignature.getR(),
            rsvSignature.getS());
        return new ResponseData<>(result, ErrorCode.SUCCESS);
    }

    /**
     * Complement the cpt json schema json string, enforcing keys to present: @schema and type.
     *
     * @param cptJsonSchemaOld the old cpt json schema json string
     * @return the new string
     */
    public static String complementCptJsonSchema(String cptJsonSchemaOld) {
        try {
            Map<String, Object> cptJsonSchemaMapOld = DataToolUtils.deserialize(
                cptJsonSchemaOld,
                HashMap.class
            );
            Map<String, Object> cptJsonSchemaMapNew = new HashMap<>();
            cptJsonSchemaMapNew.put(JsonSchemaConstant.SCHEMA_KEY, JsonSchemaConstant.SCHEMA_VALUE);
            cptJsonSchemaMapNew
                .put(JsonSchemaConstant.TYPE_KEY, JsonSchemaConstant.DATA_TYPE_OBJECT);
            cptJsonSchemaMapNew.putAll(cptJsonSchemaMapOld);
            return DataToolUtils.serialize(cptJsonSchemaMapNew);
        } catch (Exception e) {
            return StringUtils.EMPTY;
        }
    }

    /**
     * Get the current timestamp as the param "created".  Used by Restful API service.
     *
     * @param length length
     * @return the StaticArray
     */
    public static StaticArray<Int256> getParamCreated(int length) {
        long[] longArray = new long[length];
        long created = DateUtils.getNoMillisecondTimeStamp();
        longArray[1] = created;
        return DataToolUtils.longArrayToInt256StaticArray(longArray);
    }

    /**
     * Get the current timestamp as the param "updated".  Used by Restful API service.
     *
     * @param length length
     * @return the StaticArray
     */
    public static StaticArray<Int256> getParamUpdated(int length) {
        long[] longArray = new long[length];
        long created = DateUtils.getNoMillisecondTimeStamp();
        longArray[2] = created;
        return DataToolUtils.longArrayToInt256StaticArray(longArray);
    }

    /**
     * Get the cpt json schema as the param "cptJsonSchema". Used by Restful API service.
     *
     * @param cptJsonSchema the cptJsonSchema String
     * @return the StaticArray
     */
    public static StaticArray<Bytes32> getParamJsonSchema(String cptJsonSchema) {
        List<byte[]> bytes = DataToolUtils
            .stringToByte32ArrayList(cptJsonSchema, WeIdConstant.JSON_SCHEMA_ARRAY_LENGTH);
        return DataToolUtils.byteArrayListToBytes32StaticArray(bytes);
    }

    /**
     * Get a random Nonce for a transaction. Used by Restful API service.
     *
     * @return nonce in BigInt.
     */
    public static BigInteger getNonce() {
        Random r = new SecureRandom();
        return new BigInteger(250, r);
    }

    /**
     * Resolve CPT Event.
     *
     * @param retCode the retCode
     * @param cptId the CptId
     * @param cptVersion the CptVersion
     * @param receipt the transactionReceipt
     * @return the result
     */
    public static ResponseData<CptBaseInfo> getResultByResolveEvent(
        Uint256 retCode,
        Uint256 cptId,
        Int256 cptVersion,
        TransactionReceipt receipt) {

        TransactionInfo info = new TransactionInfo(receipt);
        // register
        if (DataToolUtils.uint256ToInt(retCode)
            == ErrorCode.CPT_ID_AUTHORITY_ISSUER_EXCEED_MAX.getCode()) {
            logger.error("[getResultByResolveEvent] cptId limited max value. cptId:{}",
                DataToolUtils.uint256ToInt(cptId));
            return new ResponseData<>(null, ErrorCode.CPT_ID_AUTHORITY_ISSUER_EXCEED_MAX, info);
        }

        if (DataToolUtils.uint256ToInt(retCode) == ErrorCode.CPT_ALREADY_EXIST.getCode()) {
            logger.error("[getResultByResolveEvent] cpt already exists on chain. cptId:{}",
                DataToolUtils.uint256ToInt(cptId));
            return new ResponseData<>(null, ErrorCode.CPT_ALREADY_EXIST, info);
        }

        if (DataToolUtils.uint256ToInt(retCode) == ErrorCode.CPT_NO_PERMISSION.getCode()) {
            logger.error("[getResultByResolveEvent] no permission. cptId:{}",
                DataToolUtils.uint256ToInt(cptId));
            return new ResponseData<>(null, ErrorCode.CPT_NO_PERMISSION, info);
        }

        // register and update
        if (DataToolUtils.uint256ToInt(retCode)
            == ErrorCode.CPT_PUBLISHER_NOT_EXIST.getCode()) {
            logger.error("[getResultByResolveEvent] publisher does not exist. cptId:{}",
                DataToolUtils.uint256ToInt(cptId));
            return new ResponseData<>(null, ErrorCode.CPT_PUBLISHER_NOT_EXIST, info);
        }

        // update
        if (DataToolUtils.uint256ToInt(retCode)
            == ErrorCode.CPT_NOT_EXISTS.getCode()) {
            logger.error("[getResultByResolveEvent] cpt id : {} does not exist.",
                DataToolUtils.uint256ToInt(cptId));
            return new ResponseData<>(null, ErrorCode.CPT_NOT_EXISTS, info);
        }

        CptBaseInfo result = new CptBaseInfo();
        result.setCptId(DataToolUtils.uint256ToInt(cptId));
        result.setCptVersion(DataToolUtils.int256ToInt(cptVersion));

        return new ResponseData<>(result, ErrorCode.SUCCESS, info);
    }

    /**
     * Resolve CPT Event.
     *
     * @param retCode the retCode
     * @param cptId the CptId
     * @param cptVersion the CptVersion
     * @param receipt receipt
     * @return the result
     */
    public static ResponseData<CptBaseInfo> getResultByResolveEvent(
        BigInteger retCode,
        BigInteger cptId,
        BigInteger cptVersion,
        org.fisco.bcos.sdk.model.TransactionReceipt receipt) {

        TransactionInfo info = new TransactionInfo(receipt);
        // register
        if (retCode.intValue()
            == ErrorCode.CPT_ID_AUTHORITY_ISSUER_EXCEED_MAX.getCode()) {
            logger.error("[getResultByResolveEvent] cptId limited max value. cptId:{}",
                retCode.intValue());
            return new ResponseData<>(null, ErrorCode.CPT_ID_AUTHORITY_ISSUER_EXCEED_MAX, info);
        }

        if (retCode.intValue() == ErrorCode.CPT_ALREADY_EXIST.getCode()) {
            logger.error("[getResultByResolveEvent] cpt already exists on chain. cptId:{}",
                cptId.intValue());
            return new ResponseData<>(null, ErrorCode.CPT_ALREADY_EXIST, info);
        }

        if (retCode.intValue() == ErrorCode.CPT_NO_PERMISSION.getCode()) {
            logger.error("[getResultByResolveEvent] no permission. cptId:{}",
                cptId.intValue());
            return new ResponseData<>(null, ErrorCode.CPT_NO_PERMISSION, info);
        }

        // register and update
        if (retCode.intValue() == ErrorCode.CPT_PUBLISHER_NOT_EXIST.getCode()) {
            logger.error("[getResultByResolveEvent] publisher does not exist. cptId:{}",
                cptId.intValue());
            return new ResponseData<>(null, ErrorCode.CPT_PUBLISHER_NOT_EXIST, info);
        }

        // update
        if (retCode.intValue() == ErrorCode.CPT_NOT_EXISTS.getCode()) {
            logger.error("[getResultByResolveEvent] cpt id : {} does not exist.",
                cptId.intValue());
            return new ResponseData<>(null, ErrorCode.CPT_NOT_EXISTS, info);
        }

        CptBaseInfo result = new CptBaseInfo();
        result.setCptId(cptId.intValue());
        result.setCptVersion(cptVersion.intValue());

        ResponseData<CptBaseInfo> responseData = new ResponseData<>(result, ErrorCode.SUCCESS,
            info);
        return responseData;
    }
}
