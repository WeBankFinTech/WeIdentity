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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.protocol.base.AuthorityIssuer;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.request.RegisterAuthorityIssuerArgs;
import com.webank.weid.protocol.request.RemoveAuthorityIssuerArgs;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.rpc.AuthorityIssuerService;
import com.webank.weid.rpc.WeIdService;
import com.webank.weid.util.WeIdUtils;

/**
 * Service implementations for operations on Authority Issuer.
 *
 * @author chaoxinhu 2018.10
 */
public class AuthorityIssuerServiceImpl extends AbstractService implements AuthorityIssuerService {

    private static final Logger logger = LoggerFactory
        .getLogger(AuthorityIssuerServiceImpl.class);

    private WeIdService weIdService = new WeIdServiceImpl();

    /**
     * Register a new Authority Issuer on Chain.
     *
     * @param args the args
     * @return the Boolean response data
     */
    @Override
    public ResponseData<Boolean> registerAuthorityIssuer(RegisterAuthorityIssuerArgs args) {

        ErrorCode innerResponseData = checkRegisterAuthorityIssuerArgs(args);
        if (ErrorCode.SUCCESS.getCode() != innerResponseData.getCode()) {
            return new ResponseData<>(false, innerResponseData);
        }
        try {
            return authEngine.addAuthorityIssuer(args);
        } catch (Exception e) {
            logger.error("register has error, Error Message:{}", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Remove a new Authority Issuer on Chain.
     *
     * @param args the args
     * @return the Boolean response data
     */
    @Override
    public ResponseData<Boolean> removeAuthorityIssuer(RemoveAuthorityIssuerArgs args) {

        ErrorCode innerResponseData = checkRemoveAuthorityIssuerArgs(args);
        if (ErrorCode.SUCCESS.getCode() != innerResponseData.getCode()) {
            return new ResponseData<>(false, innerResponseData);
        }

        try {
            return authEngine.removeAuthorityIssuer(args);
        } catch (Exception e) {
            logger.error("remove authority issuer failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Check whether the given weId is an authority issuer.
     *
     * @param weId the WeIdentity DID
     * @return the Boolean response data
     */
    @Override
    public ResponseData<Boolean> isAuthorityIssuer(String weId) {

        if (!WeIdUtils.isWeIdValid(weId)) {
            return new ResponseData<>(false, ErrorCode.WEID_INVALID);
        }
        String addr = WeIdUtils.convertWeIdToAddress(weId);
        try {
            return authEngine.isAuthorityIssuer(addr);
        } catch (Exception e) {
            logger.error("check authority issuer id failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR.getCode(),
                e.getMessage());
        }
    }

    /**
     * Recognize this WeID to be an authority issuer.
     *
     * @param weId the WeID
     * @param weIdPrivateKey the private key set
     * @return true if succeeds, false otherwise
     */
    @Override
    public ResponseData<Boolean> recognizeAuthorityIssuer(String weId,
        WeIdPrivateKey weIdPrivateKey) {
        if (!weIdService.isWeIdExist(weId).getResult()) {
            return new ResponseData<>(false, ErrorCode.WEID_DOES_NOT_EXIST);
        }
        if (!WeIdUtils.isPrivateKeyValid(weIdPrivateKey)) {
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        String addr = WeIdUtils.convertWeIdToAddress(weId);
        try {
            return authEngine.recognizeWeId(true, addr, weIdPrivateKey);
        } catch (Exception e) {
            logger.error("Failed to recognize authority issuer.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR.getCode(),
                e.getMessage());
        }
    }

    /**
     * De-recognize this WeID to no longer be and authority issuer.
     *
     * @param weId the WeID
     * @param weIdPrivateKey the private key set
     * @return true if succeeds, false otherwise
     */
    @Override
    public ResponseData<Boolean> deRecognizeAuthorityIssuer(String weId,
        WeIdPrivateKey weIdPrivateKey) {
        if (!weIdService.isWeIdExist(weId).getResult()) {
            return new ResponseData<>(false, ErrorCode.WEID_DOES_NOT_EXIST);
        }
        if (!WeIdUtils.isPrivateKeyValid(weIdPrivateKey)) {
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        String addr = WeIdUtils.convertWeIdToAddress(weId);
        try {
            return authEngine.recognizeWeId(false, addr, weIdPrivateKey);
        } catch (Exception e) {
            logger.error("Failed to recognize authority issuer.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR.getCode(),
                e.getMessage());
        }
    }

    /**
     * Query the authority issuer information given weId.
     *
     * @param weId the WeIdentity DID
     * @return the AuthorityIssuer response data
     */
    @Override
    public ResponseData<AuthorityIssuer> queryAuthorityIssuerInfo(String weId) {
        if (!WeIdUtils.isWeIdValid(weId)) {
            return new ResponseData<>(null, ErrorCode.WEID_INVALID);
        }
        try {
            return authEngine.getAuthorityIssuerInfoNonAccValue(weId);
        } catch (Exception e) {
            logger.error("query authority issuer failed.", e);
            return new ResponseData<>(null, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Get all of the authority issuer.
     *
     * @param index start position
     * @param num number of returned authority issuer in this request
     * @return Execution result
     */
    @Override
    public ResponseData<List<AuthorityIssuer>> getAllAuthorityIssuerList(Integer index,
        Integer num) {
        ErrorCode errorCode = isStartEndPosValid(index, num);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<>(null, errorCode);
        }
        try {
            List<String> addrList = authEngine.getAuthorityIssuerAddressList(index, num);
            List<AuthorityIssuer> authorityIssuerList = new ArrayList<>();
            for (String address : addrList) {
                String weId = WeIdUtils.convertAddressToWeId(address);
                ResponseData<AuthorityIssuer> innerResponseData
                    = this.queryAuthorityIssuerInfo(weId);
                if (innerResponseData.getResult() != null) {
                    authorityIssuerList.add(innerResponseData.getResult());
                }
            }
            return new ResponseData<>(authorityIssuerList, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("query authority issuer list failed.", e);
            return new ResponseData<>(null, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Register a new issuer type.
     *
     * @param callerAuth the caller
     * @param issuerType the specified issuer type
     * @return Execution result
     */
    @Override
    public ResponseData<Boolean> registerIssuerType(
        WeIdAuthentication callerAuth,
        String issuerType
    ) {
        ErrorCode innerCode = isIssuerTypeValid(issuerType);
        if (innerCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(false, innerCode);
        }
        innerCode = isCallerAuthValid(callerAuth);
        if (innerCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(false, innerCode);
        }
        try {
            return authEngine
                .registerIssuerType(issuerType, callerAuth.getWeIdPrivateKey());
        } catch (Exception e) {
            logger.error("register issuer type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }


    /**
     * Marked an issuer as the specified issuer type.
     *
     * @param callerAuth the caller who have the access to modify this list
     * @param issuerType the specified issuer type
     * @param targetIssuerWeId the weId of the issuer who will be marked as a specific issuer type
     * @return Execution result
     */
    @Override
    public ResponseData<Boolean> addIssuerIntoIssuerType(
        WeIdAuthentication callerAuth,
        String issuerType,
        String targetIssuerWeId
    ) {
        ErrorCode innerCode = isSpecificTypeIssuerArgsValid(callerAuth, issuerType,
            targetIssuerWeId);
        if (innerCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(false, innerCode);
        }
        try {
            String issuerAddress = WeIdUtils.convertWeIdToAddress(targetIssuerWeId);
            return authEngine.addIssuer(issuerType, issuerAddress,
                callerAuth.getWeIdPrivateKey());
        } catch (Exception e) {
            logger.error("add issuer into type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Removed an issuer from the specified issuer list.
     *
     * @param callerAuth the caller who have the access to modify this list
     * @param issuerType the specified issuer type
     * @param targetIssuerWeId the weId of the issuer to be removed from a specific issuer list
     * @return Execution result
     */
    @Override
    public ResponseData<Boolean> removeIssuerFromIssuerType(
        WeIdAuthentication callerAuth,
        String issuerType,
        String targetIssuerWeId
    ) {
        ErrorCode innerCode = isSpecificTypeIssuerArgsValid(callerAuth, issuerType,
            targetIssuerWeId);
        if (innerCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(false, innerCode);
        }
        try {
            String issuerAddress = WeIdUtils.convertWeIdToAddress(targetIssuerWeId);
            return authEngine.removeIssuer(
                issuerType,
                issuerAddress,
                callerAuth.getWeIdPrivateKey());
        } catch (Exception e) {
            logger.error("remove issuer from type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Check if the given WeId is belonging to a specific issuer type.
     *
     * @param issuerType the issuer type
     * @param targetIssuerWeId the WeId
     * @return true if yes, false otherwise
     */
    @Override
    public ResponseData<Boolean> isSpecificTypeIssuer(
        String issuerType,
        String targetIssuerWeId
    ) {
        ErrorCode errorCode = isIssuerTypeValid(issuerType);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<>(false, errorCode);
        }
        if (!weIdService.isWeIdExist(targetIssuerWeId).getResult()) {
            return new ResponseData<>(false, ErrorCode.WEID_DOES_NOT_EXIST);
        }
        try {
            String address = WeIdUtils.convertWeIdToAddress(targetIssuerWeId);
            return authEngine.isSpecificTypeIssuer(issuerType, address);
        } catch (Exception e) {
            logger.error("check issuer type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Get all specific typed issuer in a list.
     *
     * @param issuerType the issuer type
     * @param index the start position index
     * @param num the number of issuers
     * @return the list
     */
    @Override
    public ResponseData<List<String>> getAllSpecificTypeIssuerList(
        String issuerType,
        Integer index,
        Integer num
    ) {
        ErrorCode errorCode = isIssuerTypeValid(issuerType);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<>(null, errorCode);
        }
        errorCode = isStartEndPosValid(index, num);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<>(null, errorCode);
        }
        try {
            return authEngine.getSpecificTypeIssuerList(issuerType, index, num);
        } catch (Exception e) {
            logger.error("get all specific issuers failed.", e);
            return new ResponseData<>(null, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    private ErrorCode isStartEndPosValid(Integer index, Integer num) {
        if (index == null || index < 0 || num == null || num <= 0
            || num > WeIdConstant.MAX_AUTHORITY_ISSUER_LIST_SIZE) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode isSpecificTypeIssuerArgsValid(
        WeIdAuthentication callerAuth,
        String issuerType,
        String targetIssuerWeId
    ) {
        if (!WeIdUtils.isWeIdValid(targetIssuerWeId)) {
            return ErrorCode.WEID_INVALID;
        }
        if (!weIdService.isWeIdExist(targetIssuerWeId).getResult()) {
            return ErrorCode.WEID_DOES_NOT_EXIST;
        }
        ErrorCode errorCode = isCallerAuthValid(callerAuth);
        if (errorCode.getCode() == ErrorCode.SUCCESS.getCode()) {
            return isIssuerTypeValid(issuerType);
        }
        return errorCode;
    }

    private ErrorCode isCallerAuthValid(WeIdAuthentication callerAuth) {
        if (callerAuth == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (!WeIdUtils.isWeIdValid(callerAuth.getWeId())) {
            return ErrorCode.WEID_INVALID;
        }
        if (!weIdService.isWeIdExist(callerAuth.getWeId()).getResult()) {
            return ErrorCode.WEID_DOES_NOT_EXIST;
        }
        if (callerAuth.getWeIdPrivateKey() == null
            || StringUtils.isEmpty(callerAuth.getWeIdPrivateKey().getPrivateKey())) {
            return ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode isIssuerTypeValid(String issuerType) {
        if (StringUtils.isEmpty(issuerType)) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (issuerType.length() > WeIdConstant.MAX_AUTHORITY_ISSUER_NAME_LENGTH) {
            return ErrorCode.SPECIFIC_ISSUER_TYPE_ILLEGAL;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode checkRegisterAuthorityIssuerArgs(
        RegisterAuthorityIssuerArgs args) {

        if (args == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        ErrorCode errorCode = checkAuthorityIssuerArgsValidity(
            args.getAuthorityIssuer()
        );

        if (ErrorCode.SUCCESS.getCode() != errorCode.getCode()) {
            logger.error("register authority issuer format error!");
            return errorCode;
        }
        if (args.getWeIdPrivateKey() == null
            || StringUtils.isEmpty(args.getWeIdPrivateKey().getPrivateKey())) {
            return ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL;
        }
        // Need an extra check for the existence of WeIdentity DID on chain, in Register Case.
        ResponseData<Boolean> innerResponseData = weIdService
            .isWeIdExist(args.getAuthorityIssuer().getWeId());
        if (!innerResponseData.getResult()) {
            return ErrorCode.WEID_INVALID;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode checkRemoveAuthorityIssuerArgs(RemoveAuthorityIssuerArgs args) {

        if (args == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (!WeIdUtils.isWeIdValid(args.getWeId())) {
            return ErrorCode.WEID_INVALID;
        }
        if (args.getWeIdPrivateKey() == null
            || StringUtils.isEmpty(args.getWeIdPrivateKey().getPrivateKey())) {
            return ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode checkAuthorityIssuerArgsValidity(AuthorityIssuer args) {

        if (args == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (!WeIdUtils.isWeIdValid(args.getWeId())) {
            return ErrorCode.WEID_INVALID;
        }
        String name = args.getName();
        if (!isValidAuthorityIssuerBytes32Param(name)) {
            return ErrorCode.AUTHORITY_ISSUER_NAME_ILLEGAL;
        }
        String accValue = args.getAccValue();
        try {
            BigInteger accValueBigInteger = new BigInteger(accValue);
            logger.info(args.getWeId() + " accValue is: " + accValueBigInteger.longValue());
            if (accValueBigInteger.compareTo(BigInteger.ZERO) < 0) {
                return ErrorCode.AUTHORITY_ISSUER_ACCVALUE_ILLEAGAL;
            }
        } catch (Exception e) {
            logger.error("accValue is invalid.", e);
            return ErrorCode.AUTHORITY_ISSUER_ACCVALUE_ILLEAGAL;
        }

        // Check additional, optional params
        if (!StringUtils.isEmpty(args.getDescription())
            && !isValidAuthorityIssuerBytes32Param(args.getDescription())) {
            logger.error("Authority Issuer description length illegal: ", args.getDescription());
            return ErrorCode.AUTORITY_ISSUER_DESCRIPTION_ILLEGAL;
        }
        List<String> extraStr32s = args.getExtraStr32();
        List<Integer> extraInts = args.getExtraInt();
        if (!CollectionUtils.isEmpty(extraStr32s)) {
            if (extraStr32s.size() > WeIdConstant.AUTHORITY_ISSUER_EXTRA_PARAM_LENGTH) {
                logger.error("Authority Issuer extra param size exceeds maximum.");
                return ErrorCode.AUTHORITY_ISSUER_EXTRA_PARAM_ILLEGAL;
            }
            for (String extraStr : extraStr32s) {
                if (!isValidAuthorityIssuerBytes32Param(extraStr)) {
                    logger.error("Authority Issuer extra String length illegal.");
                    return ErrorCode.AUTHORITY_ISSUER_EXTRA_PARAM_ILLEGAL;
                }
            }
        }
        if (!CollectionUtils.isEmpty(extraInts)
            && extraInts.size() > WeIdConstant.AUTHORITY_ISSUER_EXTRA_PARAM_LENGTH) {
            logger.error("Authority Issuer extra param size exceeds maximum.");
            return ErrorCode.AUTHORITY_ISSUER_EXTRA_PARAM_ILLEGAL;
        }
        return ErrorCode.SUCCESS;
    }

    private boolean isValidAuthorityIssuerBytes32Param(String name) {
        return !StringUtils.isEmpty(name)
            && name.getBytes(StandardCharsets.UTF_8).length
            < WeIdConstant.MAX_AUTHORITY_ISSUER_NAME_LENGTH
            && !StringUtils.isWhitespace(name);
    }

    @Override
    public ResponseData<String> getWeIdByOrgId(String orgId) {
        if (!isValidAuthorityIssuerBytes32Param(orgId)) {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.AUTHORITY_ISSUER_NAME_ILLEGAL);
        }
        try {
            return authEngine.getWeIdFromOrgId(orgId);
        } catch (Exception e) {
            logger.error("Failed to get WeID, Error Message:{}", e);
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }
}
