/*
 *       Copyright漏 (2018-2019) WeBank Co., Ltd.
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

import java.nio.charset.StandardCharsets;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.fisco.bcos.sdk.crypto.keypair.CryptoKeyPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.exception.LoadContractException;
import com.webank.weid.exception.PrivateKeyIllegalException;
import com.webank.weid.protocol.base.PublicKeyProperty;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdDocument;
import com.webank.weid.protocol.base.WeIdPojo;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.base.WeIdPublicKey;
import com.webank.weid.protocol.request.AuthenticationArgs;
import com.webank.weid.protocol.request.CreateWeIdArgs;
import com.webank.weid.protocol.request.PublicKeyArgs;
import com.webank.weid.protocol.request.ServiceArgs;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.rpc.WeIdService;
import com.webank.weid.suite.api.crypto.params.KeyGenerator;
import com.webank.weid.util.DataToolUtils;
import com.webank.weid.util.WeIdUtils;

/**
 * Service implementations for operations on WeIdentity DID.
 *
 * @author tonychen 2018.10
 */
public class WeIdServiceImpl extends AbstractService implements WeIdService {

    /**
     * log4j object, for recording log.
     */
    private static final Logger logger = LoggerFactory.getLogger(WeIdServiceImpl.class);

    /**
     * Create a WeIdentity DID with null input param.
     *
     * @return the response data
     */
    @Override
    public ResponseData<CreateWeIdDataResult> createWeId() {

        CreateWeIdDataResult result = new CreateWeIdDataResult();
        CryptoKeyPair keyPair = KeyGenerator.createKeyPair();
        WeIdPublicKey userWeIdPublicKey = new WeIdPublicKey(keyPair.getHexPublicKey());
        result.setUserWeIdPublicKey(userWeIdPublicKey);
        WeIdPrivateKey userWeIdPrivateKey = new WeIdPrivateKey(keyPair.getHexPrivateKey());
        result.setUserWeIdPrivateKey(userWeIdPrivateKey);
        String weId = WeIdUtils.convertPublicKeyToWeId(userWeIdPublicKey);
        result.setWeId(weId);

        ResponseData<Boolean> innerResp = processCreateWeId(
            weId, userWeIdPublicKey, userWeIdPrivateKey, false);
        if (innerResp.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
            logger.error(
                "[createWeId] Create weId failed. error message is :{}",
                innerResp.getErrorMessage()
            );
            return new ResponseData<>(null,
                ErrorCode.getTypeByErrorCode(innerResp.getErrorCode()),
                innerResp.getTransactionInfo());
        }
        return new ResponseData<>(result, ErrorCode.getTypeByErrorCode(innerResp.getErrorCode()),
            innerResp.getTransactionInfo());
    }

    /**
     * Create a WeIdentity DID.
     *
     * @param createWeIdArgs the create WeIdentity DID args
     * @return the response data
     */
    @Override
    public ResponseData<String> createWeId(CreateWeIdArgs createWeIdArgs) {

        if (createWeIdArgs == null) {
            logger.error("[createWeId]: input parameter createWeIdArgs is null.");
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isPrivateKeyValid(createWeIdArgs.getWeIdPrivateKey())) {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        WeIdPrivateKey privateKey = createWeIdArgs.getWeIdPrivateKey();
        WeIdPublicKey publicKey = new WeIdPublicKey(createWeIdArgs.getPublicKey());
        if (StringUtils.isNotBlank(publicKey.getPublicKey())) {
            if (!WeIdUtils.isKeypairMatch(privateKey, publicKey)) {
                return new ResponseData<>(
                    StringUtils.EMPTY,
                    ErrorCode.WEID_PUBLICKEY_AND_PRIVATEKEY_NOT_MATCHED
                );
            }
            String weId = WeIdUtils.convertPublicKeyToWeId(publicKey);
            ResponseData<Boolean> isWeIdExistResp = this.isWeIdExist(weId);
            if (isWeIdExistResp.getResult() == null || isWeIdExistResp.getResult()) {
                logger
                    .error("[createWeId]: create weid failed, the weid :{} is already exist", weId);
                return new ResponseData<>(StringUtils.EMPTY, ErrorCode.WEID_ALREADY_EXIST);
            }
            ResponseData<Boolean> innerResp = processCreateWeId(weId, publicKey, privateKey, false);
            if (innerResp.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
                logger.error(
                    "[createWeId]: create weid failed. error message is :{}, public key is {}",
                    innerResp.getErrorMessage(),
                    publicKey
                );
                return new ResponseData<>(StringUtils.EMPTY,
                    ErrorCode.getTypeByErrorCode(innerResp.getErrorCode()),
                    innerResp.getTransactionInfo());
            }
            return new ResponseData<>(weId,
                ErrorCode.getTypeByErrorCode(innerResp.getErrorCode()),
                innerResp.getTransactionInfo());
        } else {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.WEID_PUBLICKEY_INVALID);
        }
    }

    /**
     * Get a WeIdentity DID Document.
     *
     * @param weId the WeIdentity DID
     * @return the WeIdentity DID document
     */
    @Override
    public ResponseData<WeIdDocument> getWeIdDocument(String weId) {

        if (!WeIdUtils.isWeIdValid(weId)) {
            logger.error("Input weId : {} is invalid.", weId);
            return new ResponseData<>(null, ErrorCode.WEID_INVALID);
        }
        ResponseData<WeIdDocument> weIdDocResp = weIdServiceEngine.getWeIdDocument(weId);
        return weIdDocResp;
    }

    /**
     * Get a WeIdentity DID Document Json.
     *
     * @param weId the WeIdentity DID
     * @return the WeIdentity DID document json
     */
    @Override
    public ResponseData<String> getWeIdDocumentJson(String weId) {

        ResponseData<WeIdDocument> responseData = this.getWeIdDocument(weId);
        WeIdDocument result = responseData.getResult();

        if (result == null) {
            return new ResponseData<>(
                StringUtils.EMPTY,
                ErrorCode.getTypeByErrorCode(responseData.getErrorCode())
            );
        }
        ObjectMapper mapper = new ObjectMapper();
        String weIdDocument;
        try {
            weIdDocument = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(result);
        } catch (Exception e) {
            logger.error("write object to String fail.", e);
            return new ResponseData<>(
                StringUtils.EMPTY,
                ErrorCode.getTypeByErrorCode(responseData.getErrorCode())
            );
        }
        weIdDocument =
            new StringBuffer()
                .append(weIdDocument)
                .insert(1, WeIdConstant.WEID_DOC_PROTOCOL_VERSION)
                .toString();

        ResponseData<String> responseDataJson = new ResponseData<String>();
        responseDataJson.setResult(weIdDocument);
        responseDataJson.setErrorCode(ErrorCode.getTypeByErrorCode(responseData.getErrorCode()));

        return responseDataJson;
    }

    /**
     * Remove a public key enlisted in WeID document together with the its authentication.
     *
     * @param weId the WeID to delete public key from
     * @param publicKeyArgs the public key args
     * @param privateKey the private key to send blockchain transaction
     * @return true if succeeds, false otherwise
     */
    @Override
    public ResponseData<Boolean> revokePublicKeyWithAuthentication(
        String weId,
        PublicKeyArgs publicKeyArgs,
        WeIdPrivateKey privateKey) {
        if (!verifyPublicKeyArgs(publicKeyArgs)) {
            logger.error("[removePublicKey]: input parameter setPublicKeyArgs is illegal.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isPrivateKeyValid(privateKey)) {
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }

        WeIdPublicKey weIdPublicKey = new WeIdPublicKey(publicKeyArgs.getPublicKey());
        // TODO check this weid document that this pubkey MUST exist first
        String removedPubKeyToWeId = WeIdUtils.convertPublicKeyToWeId(weIdPublicKey);
        if (removedPubKeyToWeId.equalsIgnoreCase(weId)) {
            logger.error("Cannot remove the owning public key of this WeID: {}", weId);
            return new ResponseData<>(false,
                ErrorCode.WEID_CANNOT_REMOVE_ITS_OWN_PUB_KEY_WITHOUT_BACKUP);
        }
        ResponseData<WeIdDocument> responseData = this.getWeIdDocument(weId);
        if (responseData.getResult() == null) {
            return new ResponseData<>(false,
                ErrorCode.getTypeByErrorCode(responseData.getErrorCode())
            );
        }
        List<PublicKeyProperty> publicKeys = responseData.getResult().getPublicKey();
        for (PublicKeyProperty pk : publicKeys) {
            // 这一段代码目前不会被执行到，是为了未来支持WeID authorization引入的功能
            if (pk.getPublicKey().equalsIgnoreCase(weIdPublicKey.toHex())) {
                if (publicKeys.size() == 1) {
                    logger.error("Cannot remove the last public key of this WeID: {}", weId);
                    return new ResponseData<>(false,
                        ErrorCode.WEID_CANNOT_REMOVE_ITS_OWN_PUB_KEY_WITHOUT_BACKUP);
                }
            }
        }

        // Add correct tag by externally call revokeAuthentication once
        AuthenticationArgs authenticationArgs = new AuthenticationArgs();
        authenticationArgs.setPublicKey(weIdPublicKey.toHex());
        authenticationArgs.setOwner(publicKeyArgs.getOwner());
        ResponseData<Boolean> removeAuthResp = this.revokeAuthentication(
            weId, authenticationArgs, privateKey);
        if (!removeAuthResp.getResult()) {
            logger.error("Failed to remove authentication: " + removeAuthResp.getErrorMessage());
            return removeAuthResp;
        }

        String owner = publicKeyArgs.getOwner();
        String weAddress = WeIdUtils.convertWeIdToAddress(weId);

        if (StringUtils.isEmpty(owner)) {
            owner = weAddress;
        } else {
            if (WeIdUtils.isWeIdValid(owner)) {
                owner = WeIdUtils.convertWeIdToAddress(owner);
            } else {
                logger.error("removePublicKey: owner : {} is invalid.", owner);
                return new ResponseData<>(false, ErrorCode.WEID_INVALID);
            }
        }
        try {
            String attributeKey =
                new StringBuffer()
                    .append(WeIdConstant.WEID_DOC_PUBLICKEY_PREFIX)
                    .append("/")
                    .append(publicKeyArgs.getType())
                    .append("/")
                    .append("base64")
                    .toString();
            String attrValue = new StringBuffer()
                .append(weIdPublicKey.toBase64())
                .append(WeIdConstant.REMOVED_PUBKEY_TAG).append(WeIdConstant.SEPARATOR)
                .append(owner)
                .toString();
            return weIdServiceEngine.setAttribute(
                weAddress,
                attributeKey,
                attrValue,
                privateKey,
                false);
        } catch (PrivateKeyIllegalException e) {
            logger.error("[removePublicKey] set PublicKey failed because privateKey is illegal. ",
                e);
            return new ResponseData<>(false, e.getErrorCode());
        } catch (Exception e) {
            logger.error("[removePublicKey] set PublicKey failed with exception. ", e);
            return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * Add a public key in the WeIdentity DID Document. If this key is already revoked, then it will
     * be un-revoked.
     *
     * @param weId the WeID to add public key to
     * @param publicKeyArgs the public key args
     * @param privateKey the private key to send blockchain transaction
     * @return the public key ID, -1 if any error occurred
     */
    @Override
    public ResponseData<Integer> addPublicKey(
        String weId,
        PublicKeyArgs publicKeyArgs,
        WeIdPrivateKey privateKey) {

        if (!verifyPublicKeyArgs(publicKeyArgs)) {
            logger.error("[addPublicKey]: input parameter setPublicKeyArgs is illegal.");
            return new ResponseData<>(WeIdConstant.ADD_PUBKEY_FAILURE_CODE,
                ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isPrivateKeyValid(privateKey)) {
            return new ResponseData<>(WeIdConstant.ADD_PUBKEY_FAILURE_CODE,
                ErrorCode.WEID_PRIVATEKEY_INVALID);
        }

        String weAddress = WeIdUtils.convertWeIdToAddress(weId);
        if (StringUtils.isEmpty(weAddress)) {
            logger.error("addPublicKey: weId : {} is invalid.", weId);
            return new ResponseData<>(WeIdConstant.ADD_PUBKEY_FAILURE_CODE, ErrorCode.WEID_INVALID);
        }
        ResponseData<WeIdDocument> weIdDocResp = this.getWeIdDocument(weId);
        if (weIdDocResp.getResult() == null) {
            logger.error("Failed to fetch WeID document for WeID: {}", weId);
            return new ResponseData<>(WeIdConstant.ADD_PUBKEY_FAILURE_CODE,
                ErrorCode.CREDENTIAL_WEID_DOCUMENT_ILLEGAL);
        }
        String owner = publicKeyArgs.getOwner();
        if (StringUtils.isEmpty(owner)) {
            owner = weAddress;
        } else {
            if (WeIdUtils.isWeIdValid(owner)) {
                owner = WeIdUtils.convertWeIdToAddress(owner);
            } else {
                logger.error("addPublicKey: owner : {} is invalid.", owner);
                return new ResponseData<>(WeIdConstant.ADD_PUBKEY_FAILURE_CODE,
                    ErrorCode.WEID_INVALID);
            }
        }
        WeIdPublicKey pubKey = new WeIdPublicKey(publicKeyArgs.getPublicKey());
        int currentPubKeyId = weIdDocResp.getResult().getPublicKey().size();
        for (PublicKeyProperty pkp : weIdDocResp.getResult().getPublicKey()) {
            if (pkp.getPublicKey().equalsIgnoreCase(pubKey.toHex())) {
                if (pkp.getRevoked()) {
                    currentPubKeyId = Integer
                        .valueOf(pkp.getId().substring(pkp.getId().length() - 1));
                    logger.info("Updating revocation for WeID {}, ID: {}", weId, currentPubKeyId);
                } else {
                    // Already exists and is not revoked, hence return "already exists" error
                    return new ResponseData<>(WeIdConstant.ADD_PUBKEY_FAILURE_CODE,
                        ErrorCode.WEID_PUBLIC_KEY_ALREADY_EXISTS);
                }
            }
        }
        ResponseData<Boolean> processResp = processSetPubKey(
            publicKeyArgs.getType().getTypeName(),
            weAddress,
            owner,
            pubKey,
            privateKey,
            false);
        if (!processResp.getResult()) {
            return new ResponseData<>(WeIdConstant.ADD_PUBKEY_FAILURE_CODE,
                processResp.getErrorCode(), processResp.getErrorMessage());
        } else {
            return new ResponseData<>(currentPubKeyId, ErrorCode.SUCCESS);
        }
    }

    /**
     * Set service properties.
     *
     * @param weId the WeID to set service to
     * @param serviceArgs your service name and endpoint
     * @param privateKey the private key
     * @return true if the "set" operation succeeds, false otherwise.
     */
    @Override
    public ResponseData<Boolean> setService(String weId, ServiceArgs serviceArgs,
        WeIdPrivateKey privateKey) {
        if (!verifyServiceArgs(serviceArgs)) {
            logger.error("[setService]: input parameter setServiceArgs is illegal.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isPrivateKeyValid(privateKey)) {
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        if (!verifyServiceType(serviceArgs.getType())) {
            logger.error("[setService]: the length of service type is overlimit");
            return new ResponseData<>(false, ErrorCode.WEID_SERVICE_TYPE_OVERLIMIT);
        }
        String serviceType = serviceArgs.getType();
        String serviceEndpoint = serviceArgs.getServiceEndpoint();
        return processSetService(
            privateKey,
            weId,
            serviceType,
            serviceEndpoint,
            false);

    }

    /**
     * Check if WeIdentity DID exists on Chain.
     *
     * @param weId the WeIdentity DID
     * @return true if exists, false otherwise
     */
    @Override
    public ResponseData<Boolean> isWeIdExist(String weId) {
        if (!WeIdUtils.isWeIdValid(weId)) {
            logger.error("[isWeIdExist] check weid failed. weid : {} is invalid.", weId);
            return new ResponseData<>(false, ErrorCode.WEID_INVALID);
        }
        return weIdServiceEngine.isWeIdExist(weId);
    }

    /**
     * Set authentications in WeIdentity DID.
     *
     * @param weId the WeID to set auth to
     * @param authenticationArgs A public key is needed
     * @param privateKey the private key
     * @return true if the "set" operation succeeds, false otherwise.
     */
    @Override
    public ResponseData<Boolean> setAuthentication(
        String weId,
        AuthenticationArgs authenticationArgs,
        WeIdPrivateKey privateKey) {

        if (!verifyAuthenticationArgs(authenticationArgs)) {
            logger.error("[setAuthentication]: input parameter setAuthenticationArgs is illegal.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isPrivateKeyValid(privateKey)) {
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        return processSetAuthentication(
            authenticationArgs.getOwner(),
            new WeIdPublicKey(authenticationArgs.getPublicKey()),
            privateKey,
            weId,
            false);
    }

    private ResponseData<Boolean> processSetAuthentication(
        String owner,
        WeIdPublicKey publicKey,
        WeIdPrivateKey privateKey,
        String weId,
        boolean isDelegate) {
        if (WeIdUtils.isWeIdValid(weId)) {
            ResponseData<Boolean> isWeIdExistResp = this.isWeIdExist(weId);
            if (isWeIdExistResp.getResult() == null || !isWeIdExistResp.getResult()) {
                logger.error("[setAuthentication]: failed, the weid :{} does not exist",
                    weId);
                return new ResponseData<>(false, ErrorCode.WEID_DOES_NOT_EXIST);
            }
            String weAddress = WeIdUtils.convertWeIdToAddress(weId);
            if (StringUtils.isEmpty(owner)) {
                owner = weAddress;
            } else {
                if (WeIdUtils.isWeIdValid(owner)) {
                    owner = WeIdUtils.convertWeIdToAddress(owner);
                } else {
                    logger.error("[setAuthentication]: owner : {} is invalid.", owner);
                    return new ResponseData<>(false, ErrorCode.WEID_INVALID);
                }
            }
            try {
                String attrValue = new StringBuffer()
                    .append(publicKey.toBase64())
                    .append(WeIdConstant.SEPARATOR)
                    .append(owner)
                    .toString();
                return weIdServiceEngine
                    .setAttribute(weAddress,
                        WeIdConstant.WEID_DOC_AUTHENTICATE_PREFIX,
                        attrValue,
                        privateKey,
                        isDelegate);
            } catch (PrivateKeyIllegalException e) {
                logger.error("Set authenticate with private key exception. Error message :{}", e);
                return new ResponseData<>(false, e.getErrorCode());
            } catch (Exception e) {
                logger.error("Set authenticate failed. Error message :{}", e);
                return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
            }
        } else {
            logger.error("Set authenticate failed. weid : {} is invalid.", weId);
            return new ResponseData<>(false, ErrorCode.WEID_INVALID);
        }
    }

    /**
     * Remove an authentication tag in WeID document only - will not affect its public key.
     *
     * @param weId the WeID to remove auth from
     * @param authenticationArgs A public key is needed
     * @param privateKey the private key
     * @return true if succeeds, false otherwise
     */
    @Override
    public ResponseData<Boolean> revokeAuthentication(
        String weId,
        AuthenticationArgs authenticationArgs,
        WeIdPrivateKey privateKey) {

        if (!verifyAuthenticationArgs(authenticationArgs)) {
            logger
                .error("[revokeAuthentication]: input parameter setAuthenticationArgs is illegal.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isPrivateKeyValid(privateKey)) {
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        if (WeIdUtils.isWeIdValid(weId)) {
            ResponseData<Boolean> isWeIdExistResp = this.isWeIdExist(weId);
            if (isWeIdExistResp.getResult() == null || !isWeIdExistResp.getResult()) {
                logger.error("[SetAuthentication]: failed, the weid :{} does not exist", weId);
                return new ResponseData<>(false, ErrorCode.WEID_DOES_NOT_EXIST);
            }
            String weAddress = WeIdUtils.convertWeIdToAddress(weId);

            String owner = authenticationArgs.getOwner();
            if (StringUtils.isEmpty(owner)) {
                owner = weAddress;
            } else {
                if (WeIdUtils.isWeIdValid(owner)) {
                    owner = WeIdUtils.convertWeIdToAddress(owner);
                } else {
                    logger.error("[revokeAuthentication]: owner : {} is invalid.", owner);
                    return new ResponseData<>(false, ErrorCode.WEID_INVALID);
                }
            }
            try {
                String attrValue = new StringBuffer()
                    .append(new WeIdPublicKey(authenticationArgs.getPublicKey()).toBase64())
                    .append(WeIdConstant.REMOVED_AUTHENTICATION_TAG)
                    .append(WeIdConstant.SEPARATOR)
                    .append(owner)
                    .toString();
                return weIdServiceEngine
                    .setAttribute(weAddress,
                        WeIdConstant.WEID_DOC_AUTHENTICATE_PREFIX,
                        attrValue,
                        privateKey,
                        false);
            } catch (PrivateKeyIllegalException e) {
                logger
                    .error("remove authenticate with private key exception. Error message :{}", e);
                return new ResponseData<>(false, e.getErrorCode());
            } catch (Exception e) {
                logger.error("remove authenticate failed. Error message :{}", e);
                return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
            }
        } else {
            logger.error("Set authenticate failed. weid : {} is invalid.", weId);
            return new ResponseData<>(false, ErrorCode.WEID_INVALID);
        }
    }

    private boolean verifyServiceArgs(ServiceArgs serviceArgs) {

        return !(serviceArgs == null
            || StringUtils.isBlank(serviceArgs.getType())
            || StringUtils.isBlank(serviceArgs.getServiceEndpoint()));
    }

    private boolean verifyServiceType(String type) {
        String serviceType = new StringBuffer()
            .append(WeIdConstant.WEID_DOC_SERVICE_PREFIX)
            .append(WeIdConstant.SEPARATOR)
            .append(type)
            .toString();
        int serviceTypeLength = serviceType.getBytes(StandardCharsets.UTF_8).length;
        return serviceTypeLength <= WeIdConstant.BYTES32_FIXED_LENGTH;
    }

    private ResponseData<Boolean> processCreateWeId(
        String weId,
        WeIdPublicKey publicKey,
        WeIdPrivateKey privateKey,
        boolean isDelegate) {

        String address = WeIdUtils.convertWeIdToAddress(weId);
        try {
            return weIdServiceEngine.createWeId(address, publicKey, privateKey, isDelegate);
        } catch (PrivateKeyIllegalException e) {
            logger.error("[createWeId] create weid failed because privateKey is illegal. ",
                e);
            return new ResponseData<>(false, e.getErrorCode());
        } catch (LoadContractException e) {
            logger.error("[createWeId] create weid failed because Load Contract with "
                    + "exception. ",
                e);
            return new ResponseData<>(false, e.getErrorCode());
        } catch (Exception e) {
            logger.error("[createWeId] create weid failed with exception. ", e);
            return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
        }
    }

    private boolean verifyPublicKeyArgs(PublicKeyArgs publicKeyArgs) {

        return !(publicKeyArgs == null
            || publicKeyArgs.getType() == null
            || StringUtils.isEmpty(publicKeyArgs.getType().getTypeName())
            || StringUtils.isEmpty(publicKeyArgs.getPublicKey())
            || !(isPublicKeyStringValid(publicKeyArgs.getPublicKey())));
    }

    private boolean verifyAuthenticationArgs(AuthenticationArgs authenticationArgs) {

        return !(authenticationArgs == null
            || StringUtils.isEmpty(authenticationArgs.getPublicKey())
            || !(isPublicKeyStringValid(authenticationArgs.getPublicKey())));
    }

    private boolean isPublicKeyStringValid(String pubKey) {
        // Allow base64, rsa (alphaNum) and bigInt
        return (DataToolUtils.isValidBase64String(pubKey)
            || StringUtils.isAlphanumeric(pubKey)
            || NumberUtils.isDigits(pubKey));
    }

    /* (non-Javadoc)
     * @see com.webank.weid.rpc.WeIdService#delegateCreateWeId(
     * com.webank.weid.protocol.base.WeIdPublicKey,
     * com.webank.weid.protocol.base.WeIdAuthentication)
     */
    @Override
    public ResponseData<String> delegateCreateWeId(
        WeIdPublicKey publicKey,
        WeIdAuthentication weIdAuthentication) {

        if (publicKey == null || weIdAuthentication == null) {
            logger.error("[delegateCreateWeId]: input parameter is null.");
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isPrivateKeyValid(weIdAuthentication.getWeIdPrivateKey())) {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        WeIdPrivateKey privateKey = weIdAuthentication.getWeIdPrivateKey();
        WeIdPublicKey pubKey = new WeIdPublicKey(publicKey.getPublicKey());
        if (StringUtils.isNotBlank(pubKey.getPublicKey())) {
            String weId = WeIdUtils.convertPublicKeyToWeId(pubKey);
            ResponseData<Boolean> isWeIdExistResp = this.isWeIdExist(weId);
            if (isWeIdExistResp.getResult() == null || isWeIdExistResp.getResult()) {
                logger
                    .error(
                        "[delegateCreateWeId]: create weid failed, the weid :{} is already exist",
                        weId);
                return new ResponseData<>(StringUtils.EMPTY, ErrorCode.WEID_ALREADY_EXIST);
            }
            ResponseData<Boolean> innerResp = processCreateWeId(weId, pubKey, privateKey, true);
            if (innerResp.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
                logger.error(
                    "[delegateCreateWeId]: create weid failed. error message is :{}, "
                        + "public key is {}",
                    innerResp.getErrorMessage(),
                    publicKey
                );
                return new ResponseData<>(StringUtils.EMPTY,
                    ErrorCode.getTypeByErrorCode(innerResp.getErrorCode()),
                    innerResp.getTransactionInfo());
            }
            return new ResponseData<>(weId,
                ErrorCode.getTypeByErrorCode(innerResp.getErrorCode()),
                innerResp.getTransactionInfo());
        } else {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.WEID_PUBLICKEY_INVALID);
        }
    }

    /**
     * Add a public key in the WeIdentity DID Document by other delegate caller (currently it must
     * be admin / committee). If this key is already revoked, then it will be un-revoked.
     *
     * @param weId the WeID to add public key to
     * @param publicKeyArgs the set public key args
     * @param delegateAuth the delegate's auth
     * @return the public key ID, -1 if any error occurred
     */
    @Override
    public ResponseData<Integer> delegateAddPublicKey(
        String weId,
        PublicKeyArgs publicKeyArgs,
        WeIdPrivateKey delegateAuth
    ) {
        if (delegateAuth == null) {
            return new ResponseData<>(WeIdConstant.ADD_PUBKEY_FAILURE_CODE,
                ErrorCode.ILLEGAL_INPUT);
        }
        if (publicKeyArgs == null || StringUtils.isEmpty(publicKeyArgs.getPublicKey())) {
            return new ResponseData<>(WeIdConstant.ADD_PUBKEY_FAILURE_CODE,
                ErrorCode.WEID_PUBLICKEY_INVALID);
        }
        if (!WeIdUtils.isPrivateKeyValid(delegateAuth)) {
            return new ResponseData<>(WeIdConstant.ADD_PUBKEY_FAILURE_CODE,
                ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        String weAddress = WeIdUtils.convertWeIdToAddress(weId);
        if (StringUtils.isEmpty(weAddress)) {
            logger.error("addPublicKey: weId : {} is invalid.", weId);
            return new ResponseData<>(WeIdConstant.ADD_PUBKEY_FAILURE_CODE, ErrorCode.WEID_INVALID);
        }
        ResponseData<WeIdDocument> weIdDocResp = this.getWeIdDocument(weId);
        if (weIdDocResp.getResult() == null) {
            logger.error("Failed to fetch WeID document for WeID: {}", weId);
            return new ResponseData<>(WeIdConstant.ADD_PUBKEY_FAILURE_CODE,
                ErrorCode.CREDENTIAL_WEID_DOCUMENT_ILLEGAL);
        }
        String owner = publicKeyArgs.getOwner();
        if (StringUtils.isEmpty(owner)) {
            owner = weAddress;
        } else {
            if (WeIdUtils.isWeIdValid(owner)) {
                owner = WeIdUtils.convertWeIdToAddress(owner);
            } else {
                logger.error("addPublicKey: owner : {} is invalid.", owner);
                return new ResponseData<>(WeIdConstant.ADD_PUBKEY_FAILURE_CODE,
                    ErrorCode.WEID_INVALID);
            }
        }
        WeIdPublicKey pubKey = new WeIdPublicKey(publicKeyArgs.getPublicKey());
        int currentPubKeyId = weIdDocResp.getResult().getPublicKey().size();
        for (PublicKeyProperty pkp : weIdDocResp.getResult().getPublicKey()) {
            if (pkp.getPublicKey().equalsIgnoreCase(pubKey.getPublicKey())) {
                if (pkp.getRevoked()) {
                    currentPubKeyId = Integer
                        .valueOf(pkp.getId().substring(pkp.getId().length() - 1));
                    logger.info("Updating revocation for WeID {}, ID: {}", weId, currentPubKeyId);
                } else {
                    // Already exists and is not revoked, hence return "already exists" error
                    return new ResponseData<>(WeIdConstant.ADD_PUBKEY_FAILURE_CODE,
                        ErrorCode.WEID_PUBLIC_KEY_ALREADY_EXISTS);
                }
            }
        }

        ResponseData<Boolean> processResp = processSetPubKey(
            publicKeyArgs.getType().getTypeName(),
            weAddress,
            owner,
            pubKey,
            delegateAuth,
            true);
        if (!processResp.getResult()) {
            return new ResponseData<>(WeIdConstant.ADD_PUBKEY_FAILURE_CODE,
                processResp.getErrorCode(), processResp.getErrorMessage());
        } else {
            return new ResponseData<>(currentPubKeyId, ErrorCode.SUCCESS);
        }
    }

    private ResponseData<Boolean> processSetPubKey(
        String type,
        String weAddress,
        String owner,
        WeIdPublicKey pubKey,
        WeIdPrivateKey privateKey,
        boolean isDelegate) {

        try {
            String attributeKey =
                new StringBuffer()
                    .append(WeIdConstant.WEID_DOC_PUBLICKEY_PREFIX)
                    .append("/")
                    .append(type)
                    .append("/")
                    .append("base64")
                    .toString();
            String attrValue = new StringBuffer()
                 .append(pubKey.toBase64())
                 .append(WeIdConstant.SEPARATOR)
                .append(owner).toString();
            return weIdServiceEngine.setAttribute(
                weAddress,
                attributeKey,
                attrValue,
                privateKey,
                isDelegate);
        } catch (PrivateKeyIllegalException e) {
            logger.error("[addPublicKey] set PublicKey failed because privateKey is illegal. ",
                e);
            return new ResponseData<>(false, e.getErrorCode());
        } catch (Exception e) {
            logger.error("[addPublicKey] set PublicKey failed with exception. ", e);
            return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * Set service properties.
     *
     * @param serviceArgs your service name and endpoint
     * @param delegateAuth the delegate's auth
     * @return true if the "set" operation succeeds, false otherwise.
     */
    @Override
    public ResponseData<Boolean> delegateSetService(
        String weId,
        ServiceArgs serviceArgs,
        WeIdPrivateKey delegateAuth
    ) {
        if (delegateAuth == null) {
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (serviceArgs == null || StringUtils.isEmpty(serviceArgs.getServiceEndpoint())
            || !WeIdUtils.isWeIdValid(weId)) {
            logger.error("[setService]: input parameter setServiceArgs is illegal.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isPrivateKeyValid(delegateAuth)) {
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        if (!verifyServiceType(serviceArgs.getType())) {
            logger.error("[setService]: the length of service type is overlimit");
            return new ResponseData<>(false, ErrorCode.WEID_SERVICE_TYPE_OVERLIMIT);
        }
        String serviceType = serviceArgs.getType();
        String serviceEndpoint = serviceArgs.getServiceEndpoint();
        return processSetService(
            delegateAuth,
            weId,
            serviceType,
            serviceEndpoint,
            true);
    }

    private ResponseData<Boolean> processSetService(
        WeIdPrivateKey privateKey,
        String weId,
        String serviceType,
        String serviceEndpoint,
        boolean isDelegate
    ) {
        if (WeIdUtils.isWeIdValid(weId)) {
            ResponseData<Boolean> isWeIdExistResp = this.isWeIdExist(weId);
            if (isWeIdExistResp.getResult() == null || !isWeIdExistResp.getResult()) {
                logger.error("[SetService]: failed, the weid :{} does not exist", weId);
                return new ResponseData<>(false, ErrorCode.WEID_DOES_NOT_EXIST);
            }
            try {
                // Service type is defined in key hence use the old slash identifier
                String attributeKey = new StringBuffer()
                    .append(WeIdConstant.WEID_DOC_SERVICE_PREFIX)
                    .append("/")
                    .append(serviceType)
                    .toString();
                return weIdServiceEngine
                    .setAttribute(
                        WeIdUtils.convertWeIdToAddress(weId),
                        attributeKey,
                        serviceEndpoint,
                        privateKey,
                        isDelegate);

            } catch (PrivateKeyIllegalException e) {
                logger
                    .error("[setService] set PublicKey failed because privateKey is illegal. ",
                        e);
                return new ResponseData<>(false, e.getErrorCode());
            } catch (Exception e) {
                logger.error("[setService] set service failed. Error message :{}", e);
                return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
            }
        } else {
            logger.error("[setService] set service failed, weid -->{} is invalid.", weId);
            return new ResponseData<>(false, ErrorCode.WEID_INVALID);
        }
    }

    /**
     * Set authentications in WeIdentity DID.
     *
     * @param weId the WeID to set auth to
     * @param authenticationArgs A public key is needed.
     * @param delegateAuth the delegate's auth
     * @return true if the "set" operation succeeds, false otherwise.
     */
    @Override
    public ResponseData<Boolean> delegateSetAuthentication(
        String weId,
        AuthenticationArgs authenticationArgs,
        WeIdPrivateKey delegateAuth
    ) {
        if (delegateAuth == null) {
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (authenticationArgs == null || !WeIdUtils.isWeIdValid(weId)
            || StringUtils.isEmpty(authenticationArgs.getPublicKey())) {
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isPrivateKeyValid(delegateAuth)) {
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        return processSetAuthentication(
            authenticationArgs.getOwner(),
            new WeIdPublicKey(authenticationArgs.getPublicKey()),
            delegateAuth,
            weId,
            true);
    }

    @Override
    public ResponseData<List<WeIdPojo>> getWeIdList(
        Integer blockNumber,
        Integer pageSize,
        Integer indexInBlock,
        boolean direction
    ) {
        try {
            logger.info("[getWeIdList] begin get weIdList, blockNumber = {}, pageSize = {}, "
                + "indexInBlock = {}, direction = {}", 
                blockNumber, 
                pageSize, 
                indexInBlock, 
                direction
            );
            return weIdServiceEngine.getWeIdList(blockNumber, pageSize, indexInBlock, direction);
        } catch (Exception e) {
            logger.error("[getWeIdList] get weIdList failed with exception. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    @Override
    public ResponseData<Integer> getWeIdCount() {
        return weIdServiceEngine.getWeIdCount();
    }
}
