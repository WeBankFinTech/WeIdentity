/*
 *       Copyright© (2018-2020) WeBank Co., Ltd.
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

import java.io.File;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.google.common.base.Charsets;
import com.google.common.io.Files;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.ProcessingMode;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.protocol.base.CredentialPojo;
import com.webank.weid.protocol.base.EvidenceInfo;
import com.webank.weid.protocol.base.EvidenceSignInfo;
import com.webank.weid.protocol.base.HashString;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdDocument;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.inf.Hashable;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.rpc.EvidenceService;
import com.webank.weid.rpc.WeIdService;
import com.webank.weid.service.impl.engine.EngineFactory;
import com.webank.weid.service.impl.engine.EvidenceServiceEngine;
import com.webank.weid.util.BatchTransactionUtils;
import com.webank.weid.util.CredentialPojoUtils;
import com.webank.weid.util.DataToolUtils;
import com.webank.weid.util.DateUtils;
import com.webank.weid.util.WeIdUtils;

/**
 * Service implementations for operations on Evidence.
 *
 * @author chaoxinhu 2019.1
 */
public class EvidenceServiceImpl extends AbstractService implements EvidenceService {

    private static final Logger logger = LoggerFactory.getLogger(EvidenceServiceImpl.class);

    private WeIdService weIdService = new WeIdServiceImpl();

    private ProcessingMode processingMode = ProcessingMode.IMMEDIATE;

    private EvidenceServiceEngine evidenceServiceEngine;

    private Integer groupId;

    public EvidenceServiceImpl() {
        super();
        initEvidenceServiceEngine(masterGroupId);
    }

    /**
     * 传入processingMode来决定上链模式.
     *
     * @param processingMode 上链模式
     * @param groupId 群组编号
     */
    public EvidenceServiceImpl(ProcessingMode processingMode, Integer groupId) {
        this.processingMode = processingMode;
        initEvidenceServiceEngine(groupId);
    }

    private void initEvidenceServiceEngine(Integer groupId) {
        evidenceServiceEngine = EngineFactory.createEvidenceServiceEngine(groupId);
        this.groupId = groupId;
    }

    @Override
    public ResponseData<Boolean> createRawEvidenceWithCustomKey(
        String hashValue,
        String signature,
        String log,
        Long timestamp,
        String extraKey,
        String privateKey
    ) {
        ResponseData<String> hashResp = evidenceServiceEngine.createEvidenceWithCustomKey(
            hashValue,
            signature,
            log,
            timestamp,
            extraKey,
            privateKey
        );
        if (hashResp.getResult().equalsIgnoreCase(hashValue)) {
            return new ResponseData<>(true, ErrorCode.SUCCESS);
        } else {
            return new ResponseData<>(false, hashResp.getErrorCode(), hashResp.getErrorMessage());
        }
    }


    @Override
    public ResponseData<Boolean> createRawEvidenceWithSpecificSigner(
        String hashValue,
        String signature,
        String log,
        Long timestamp,
        String extraKey,
        String signer,
        String privateKey
    ) {
        List<String> hashValues = new ArrayList<>();
        hashValues.add(hashValue);
        List<String> signatures = new ArrayList<>();
        signatures.add(signature);
        List<String> logs = new ArrayList<>();
        logs.add(log);
        List<Long> timestamps = new ArrayList<>();
        timestamps.add(timestamp);
        List<String> signers = new ArrayList<>();
        signers.add(signer);
        if (StringUtils.isEmpty(extraKey)) {
            ResponseData<List<Boolean>> resp = evidenceServiceEngine.batchCreateEvidence(
                hashValues, signatures, logs, timestamps, signers, privateKey);
            return new ResponseData<>(resp.getResult().get(0), resp.getErrorCode(),
                resp.getErrorMessage());
        } else {
            List<String> extraKeys = new ArrayList<>();
            extraKeys.add(extraKey);
            ResponseData<List<Boolean>> resp = evidenceServiceEngine
                .batchCreateEvidenceWithCustomKey(hashValues, signatures, logs, timestamps,
                    signers, extraKeys, privateKey);
            return new ResponseData<>(resp.getResult().get(0), resp.getErrorCode(),
                resp.getErrorMessage());
        }
    }

    /**
     * Create a new evidence to the blockchain and get the evidence address.
     *
     * @param object the given Java object
     * @param weIdPrivateKey the caller WeID Authentication
     * @return Evidence address
     */
    @Override
    public ResponseData<String> createEvidence(Hashable object, WeIdPrivateKey weIdPrivateKey) {
        ResponseData<String> hashResp = getHashValue(object);
        if (StringUtils.isEmpty(hashResp.getResult())) {
            return new ResponseData<>(StringUtils.EMPTY, hashResp.getErrorCode(),
                hashResp.getErrorMessage());
        }
        if (!WeIdUtils.isPrivateKeyValid(weIdPrivateKey)) {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        return hashToNewEvidence(hashResp.getResult(), weIdPrivateKey.getPrivateKey(),
            StringUtils.EMPTY);
    }

    /**
     * Create a new evidence to blockchain and return the hash value, with appending log. This will
     * fail if evidence already exists.
     *
     * @param object the given Java object
     * @param log appendable log entry - can be null or empty
     * @param weIdAuthentication weid authentication (only checks private key)
     */
    @Override
    public ResponseData<String> createEvidenceWithLog(
        Hashable object,
        String log,
        WeIdAuthentication weIdAuthentication
    ) {
        ResponseData<String> hashResp = getHashValue(object);
        if (StringUtils.isEmpty(hashResp.getResult())) {
            return new ResponseData<>(StringUtils.EMPTY, hashResp.getErrorCode(),
                hashResp.getErrorMessage());
        }
        if (weIdAuthentication == null
            || !WeIdUtils.isPrivateKeyValid(weIdAuthentication.getWeIdPrivateKey())) {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        if (!DataToolUtils.isUtf8String(log)) {
            logger.error("Evidence argument illegal input: log.");
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT);
        }
        if (!isChainStringLengthValid(log)) {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ON_CHAIN_STRING_TOO_LONG);
        }
        return hashToNewEvidence(
            hashResp.getResult(),
            weIdAuthentication.getWeIdPrivateKey().getPrivateKey(),
            log);
    }

    /**
     * Add log entry for an existing evidence. This log will be recorded on blockchain permanently,
     * and finally it will be fetched as a list when trying to get evidence.
     *
     * @param hashValue hash value
     * @param log not null log entry
     * @param weIdPrivateKey the signer WeID's private key
     */
    @Override
    public ResponseData<Boolean> addLogByHash(String hashValue, String log,
        WeIdPrivateKey weIdPrivateKey) {
        return addByHash(
            hashValue,
            log,
            weIdPrivateKey,
            false
        );
    }

    /**
     * Add signature and log as a new signer to an existing evidence. Log can be empty.
     *
     * @param hashValue hash value
     * @param log log entry
     * @param weIdPrivateKey the signer WeID's private key
     * @return true if succeeded, false otherwise
     */
    @Override
    public ResponseData<Boolean> addSignatureAndLogByHash(String hashValue, String log,
        WeIdPrivateKey weIdPrivateKey) {
        return addByHash(
            hashValue,
            log,
            weIdPrivateKey,
            true
        );
    }

    private ResponseData<Boolean> addByHash(
        String hashValue,
        String log,
        WeIdPrivateKey weIdPrivateKey,
        boolean requireSig
    ) {
        if (!DataToolUtils.isValidHash(hashValue) || (StringUtils.isEmpty(log) && !requireSig)
            || !DataToolUtils.isUtf8String(log)) {
            logger.error("Evidence argument illegal input: hash or log.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!isChainStringLengthValid(log)) {
            return new ResponseData<>(false, ErrorCode.ON_CHAIN_STRING_TOO_LONG);
        }
        if (!WeIdUtils.isPrivateKeyValid(weIdPrivateKey)) {
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        Long timestamp = DateUtils.getNoMillisecondTimeStamp();
        if (requireSig) {
            String signature = DataToolUtils.secp256k1Sign(hashValue,
                new BigInteger(weIdPrivateKey.getPrivateKey()));
            return evidenceServiceEngine.addLog(
                hashValue,
                signature,
                log,
                timestamp,
                weIdPrivateKey.getPrivateKey()
            );
        } else {
            return evidenceServiceEngine.addLog(
                hashValue,
                StringUtils.EMPTY,
                log,
                timestamp,
                weIdPrivateKey.getPrivateKey()
            );
        }
    }

    /**
     * Add log entry for an existing evidence, appending on existing log entries. This log will be
     * recorded on blockchain permanently, and finally it will be fetched as a list when trying to
     * get evidence. Log must not be empty. It will firstly try to fetch the hash value given the
     * custom key, and if the hash value does not exist, it will use the supplementing hash value
     * (1st parameter) to make up.
     *
     * @param hashValueSupplement the hash value supplement if the custom key does not exist
     * @param customKey custom key
     * @param log Not null log entry
     * @param weIdPrivateKey the signer WeID's private key
     * @return true if succeeded, false otherwise
     */
    @Override
    public ResponseData<Boolean> addLogByCustomKey(
        String hashValueSupplement,
        String customKey,
        String log,
        WeIdPrivateKey weIdPrivateKey) {
        return addByCustomKey(
            hashValueSupplement,
            customKey,
            log,
            weIdPrivateKey,
            false
        );
    }

    /**
     * Add signature and log as a new signer to an existing evidence. Log can be empty.
     *
     * @param hashValueSupplement the hash value supplement if the custom key does not exist
     * @param customKey custom key
     * @param log log entry
     * @param weIdPrivateKey the signer WeID's private key
     * @return true if succeeded, false otherwise
     */
    @Override
    public ResponseData<Boolean> addSignatureAndLogByCustomKey(
        String hashValueSupplement,
        String customKey,
        String log,
        WeIdPrivateKey weIdPrivateKey
    ) {
        return addByCustomKey(
            hashValueSupplement,
            customKey,
            log,
            weIdPrivateKey,
            true
        );
    }

    private ResponseData<Boolean> addByCustomKey(
        String hashValueSupplement,
        String customKey,
        String log,
        WeIdPrivateKey weIdPrivateKey,
        boolean requireSig
    ) {
        if ((StringUtils.isEmpty(log) && !requireSig) || !DataToolUtils.isUtf8String(log)) {
            logger.error("Evidence argument illegal input: log.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (StringUtils.isEmpty(customKey) || !DataToolUtils.isUtf8String(customKey)) {
            logger.error("Evidence argument illegal input: customKey.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!isChainStringLengthValid(log)) {
            return new ResponseData<>(false, ErrorCode.ON_CHAIN_STRING_TOO_LONG);
        }
        ResponseData<String> hashResp = evidenceServiceEngine.getHashByCustomKey(customKey);
        String hashValue = hashResp.getResult();
        if (StringUtils.isEmpty(hashValue)) {
            logger.error("Failed to find the hash value from custom key: ", customKey);
            if (StringUtils.isEmpty(hashValueSupplement)) {
                return new ResponseData<>(false, hashResp.getErrorCode(),
                    hashResp.getErrorMessage());
            }
            hashValue = hashValueSupplement;
        }
        Long timestamp = DateUtils.getNoMillisecondTimeStamp();
        if (requireSig) {
            String signature = DataToolUtils.secp256k1Sign(hashValue,
                new BigInteger(weIdPrivateKey.getPrivateKey()));
            return evidenceServiceEngine.addLogByCustomKey(
                hashValue,
                signature,
                log,
                timestamp,
                customKey,
                weIdPrivateKey.getPrivateKey()
            );
        } else {
            return evidenceServiceEngine.addLogByCustomKey(
                hashValue,
                StringUtils.EMPTY,
                log,
                timestamp,
                customKey,
                weIdPrivateKey.getPrivateKey()
            );
        }
    }

    /* (non-Javadoc)
     * @see com.webank.weid.rpc.generateHash
     * #generateHash(T object)
     */
    @Override
    public <T> ResponseData<HashString> generateHash(T object) {
        if (object == null) {
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        if (object instanceof Hashable) {
            ResponseData<String> hashResp = getHashValue((Hashable) object);
            if (StringUtils.isEmpty(hashResp.getResult())) {
                return new ResponseData<>(null, hashResp.getErrorCode(),
                    hashResp.getErrorMessage());
            }
            return new ResponseData<>(new HashString(hashResp.getResult()), ErrorCode.SUCCESS);
        }
        if (object instanceof File) {
            // This will convert all types of file into String stream
            String rawData = convertFileToString((File) object);
            if (StringUtils.isEmpty(rawData)) {
                logger.error("Failed to convert file into String: {}", ((File) object).getName());
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }
            return new ResponseData<>(new HashString(DataToolUtils.sha3(rawData)),
                ErrorCode.SUCCESS);
        }
        if (object instanceof String) {
            if (StringUtils.isEmpty((String) object)) {
                logger.error("Input String is blank, ignored..");
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }
            return new ResponseData<>(new HashString(DataToolUtils.sha3((String) object)),
                ErrorCode.SUCCESS);
        }
        logger.error("Unsupported input object type: {}", object.getClass().getCanonicalName());
        return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
    }

    private String convertFileToString(File file) {
        try {
            return Files.asByteSource(file).asCharSource(Charsets.UTF_8).read();
        } catch (Exception e) {
            logger.error("Failed to load file as String.", e);
            return StringUtils.EMPTY;
        }
    }

    /**
     * Obtain the hash value of a given object - supports Credential, Wrapper and Pojo, and also
     * plain hash value (no extra hashing required).
     *
     * @param object any object
     * @return hash value
     */
    private ResponseData<String> getHashValue(Hashable object) {
        if (object == null) {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT);
        }
        try {
            String hashValue = object.getHash();
            if (StringUtils.isEmpty(hashValue)) {
                return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT);
            }
            return new ResponseData<>(hashValue, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("Input Object type unsupported: {}", object.getClass().getName(), e);
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT);
        }
    }

    /**
     * Actual method to upload to blockchain, varied in different blockchain versions.
     *
     * @param hashValue the hash value to be uploaded
     * @param privateKey the private key to reload contract and sign txn
     * @param extra the extra value (compact json formatted blob)
     */
    private ResponseData<String> hashToNewEvidence(String hashValue, String privateKey,
        String extra) {
        try {
            String signature = DataToolUtils.secp256k1Sign(hashValue, new BigInteger(privateKey));
            Long timestamp = DateUtils.getCurrentTimeStamp();
            if (processingMode == ProcessingMode.PERIODIC_AND_BATCH) {
                String[] args = new String[6];
                args[0] = hashValue;
                args[1] = signature;
                args[2] = extra;
                args[3] = String.valueOf(timestamp);
                args[4] = privateKey;
                args[5] = String.valueOf(this.groupId);
                String rawData = new StringBuffer()
                    .append(hashValue)
                    .append(signature)
                    .append(extra)
                    .append(timestamp)
                    .append(WeIdUtils.getWeIdFromPrivateKey(privateKey))
                    .append(this.groupId).toString();
                String hash = DataToolUtils.sha3(rawData);
                String requestId = new BigInteger(hash.substring(2), 16).toString();
                boolean isSuccess = BatchTransactionUtils
                    .writeTransaction(requestId, "createEvidence", args, StringUtils.EMPTY);
                if (isSuccess) {
                    return new ResponseData<>(hashValue, ErrorCode.SUCCESS);
                } else {
                    return new ResponseData<>(hashValue, ErrorCode.OFFLINE_EVIDENCE_SAVE_FAILED);
                }
            }

            return evidenceServiceEngine.createEvidence(
                hashValue,
                signature,
                extra,
                timestamp,
                privateKey
            );
        } catch (Exception e) {
            logger.error("create evidence failed due to system error. ", e);
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR);
        }
    }

    /**
     * Get the evidence from blockchain.
     *
     * @param evidenceKey the evidence hash on chain
     * @return The EvidenceInfo
     */
    @Override
    public ResponseData<EvidenceInfo> getEvidence(String evidenceKey) {
        if (!DataToolUtils.isValidHash(evidenceKey)) {
            logger.error("Evidence argument illegal input: evidence hash. ");
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        try {
            return evidenceServiceEngine.getInfo(evidenceKey);
        } catch (Exception e) {
            logger.error("get evidence failed.", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR);
        }
    }

    /**
     * Validate whether a credential created the evidence, and this evidence is signed by this WeID
     * - will perform on-Chain key check.
     *
     * @param credentialPojo the credentialPojo
     * @param evidenceInfo the evidence info fetched from chain
     * @param weId the WeID
     * @return true if yes, false otherwise
     */
    @Override
    public ResponseData<Boolean> verifySigner(
        CredentialPojo credentialPojo,
        EvidenceInfo evidenceInfo,
        String weId
    ) {
        return verifySigner(credentialPojo, evidenceInfo, weId, null);
    }

    /**
     * Validate whether a credential created the evidence, and this evidence is signed by this WeID
     * based on the passed-in publicKey.
     *
     * @param credentialPojo the credentialPojo
     * @param evidenceInfo the evidence info fetched from chain
     * @param weId the WeID
     * @param publicKey the public key
     * @return true if yes, false otherwise
     */
    @Override
    public ResponseData<Boolean> verifySigner(
        CredentialPojo credentialPojo,
        EvidenceInfo evidenceInfo,
        String weId,
        String publicKey) {
        if (evidenceInfo == null || evidenceInfo.getSigners().isEmpty()) {
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isWeIdValid(weId)) {
            return new ResponseData<>(false, ErrorCode.WEID_INVALID);
        }
        if (!evidenceInfo.getSigners().contains(weId)) {
            logger.error("This Evidence does not contain the provided WeID: {}", weId);
            return new ResponseData<>(false, ErrorCode.WEID_DOES_NOT_EXIST);
        }

        // 1st: verify hash (accept both thumbprint hash or credential.getHash())
        if (!evidenceInfo.getCredentialHash().equalsIgnoreCase(credentialPojo.getHash())) {
            if (CredentialPojoUtils.isLiteCredential(credentialPojo)) {
                if (!evidenceInfo.getCredentialHash().equalsIgnoreCase(DataToolUtils.sha3(
                    CredentialPojoUtils.getLiteCredentialThumbprintWithoutSig(credentialPojo)))) {
                    logger.error("Evidence hash mismatches the lite credential hash or thumbprint");
                    return new ResponseData<>(false, ErrorCode.CREDENTIAL_EVIDENCE_HASH_MISMATCH);
                }
            } else {
                if (CredentialPojoUtils.isEmbeddedCredential(credentialPojo)) {
                    // Currently unsupported for embedded credential thumbprint hash case
                    logger.error("Evidence hash mismatches the embedded credential hash");
                    return new ResponseData<>(false, ErrorCode.CREDENTIAL_EVIDENCE_HASH_MISMATCH);
                } else {
                    if (!evidenceInfo.getCredentialHash().equalsIgnoreCase(
                        DataToolUtils.sha3(
                            CredentialPojoUtils.getCredentialThumbprintWithoutSig(credentialPojo,
                                credentialPojo.getSalt(), null)))) {
                        logger.error("Evidence hash mismatches the non-embedded credential hash or"
                            + "thumbprint");
                        return new ResponseData<>(false,
                            ErrorCode.CREDENTIAL_EVIDENCE_HASH_MISMATCH);
                    }
                }
            }
        }

        // 2nd: verify signer = issuer
        if (!credentialPojo.getIssuer().equalsIgnoreCase(weId)) {
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_ISSUER_MISMATCH);
        }

        // 3rd: verify signature w.r.t. weid (must exist and must be the signer (from pubkey))
        EvidenceSignInfo signInfo = evidenceInfo.getSignInfo().get(weId);
        String signature = signInfo.getSignature();
        if (!DataToolUtils.isValidBase64String(signature)) {
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_EVIDENCE_SIGNATURE_BROKEN);
        }

        // Firstly, we check the secp256k1 style signature
        if (StringUtils.isEmpty(publicKey)) {
            ResponseData<Boolean> verifyResp = verifySecp256k1SignatureToSigner(
                evidenceInfo.getCredentialHash(),
                WeIdUtils.convertAddressToWeId(weId),
                signature);
            return verifyResp;
        } else {
            try {
                boolean result = DataToolUtils
                    .verifySecp256k1Signature(evidenceInfo.getCredentialHash(), signature,
                        new BigInteger(publicKey));

                if (!result) {
                    logger.error("Public key does not match signature.");
                    return new ResponseData<>(false, ErrorCode.CREDENTIAL_SIGNATURE_BROKEN);
                }
                return new ResponseData<>(true, ErrorCode.SUCCESS);
            } catch (Exception e) {
                logger.error("Passed-in signature illegal");
                return new ResponseData<>(false, ErrorCode.WEID_PUBLICKEY_INVALID);
            }
        }
    }

    private ResponseData<Boolean> verifySecp256k1SignatureToSigner(
        String rawData,
        String signerWeId,
        String secp256k1sig
    ) {
        try {
            ResponseData<WeIdDocument> innerResponseData =
                weIdService.getWeIdDocument(signerWeId);
            if (innerResponseData.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
                logger.error(
                    "Error occurred when fetching WeIdentity DID document for: {}, msg: {}",
                    signerWeId, innerResponseData.getErrorMessage());
                return new ResponseData<>(false, ErrorCode.CREDENTIAL_WEID_DOCUMENT_ILLEGAL);
            }
            WeIdDocument weIdDocument = innerResponseData.getResult();
            ErrorCode errorCode = DataToolUtils
                .verifySecp256k1SignatureFromWeId(rawData, secp256k1sig, weIdDocument, null);
            if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
                return new ResponseData<>(false, errorCode);
            }
            return new ResponseData<>(true, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("error occurred during verifying signatures from chain: ", e);
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR);
        }
    }

    /* (non-Javadoc)
     * @see com.webank.weid.rpc.EvidenceService#createEvidenceWithLogAndCustomKey(
     * com.webank.weid.protocol.inf.Hashable, com.webank.weid.protocol.base.WeIdPrivateKey,
     * java.lang.String)
     */
    @Override
    public ResponseData<String> createEvidenceWithLogAndCustomKey(
        Hashable object,
        WeIdPrivateKey weIdPrivateKey,
        String log,
        String customKey) {
        if (StringUtils.isEmpty(customKey) || DataToolUtils.isValidHash(customKey)) {
            logger.error("Custom key must be non-empty and must not be of hash format.");
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT);
        }
        if (!DataToolUtils.isUtf8String(log)) {
            logger.error("Log format illegal.");
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT);
        }
        if (StringUtils.isEmpty(log)) {
            log = StringUtils.EMPTY;
        }
        if (!isChainStringLengthValid(log) || !isChainStringLengthValid(customKey)) {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ON_CHAIN_STRING_TOO_LONG);
        }
        if (StringUtils.isEmpty(customKey)) {
            customKey = StringUtils.EMPTY;
        }
        ResponseData<String> hashResp = getHashValue(object);
        String hashValue = hashResp.getResult();
        if (StringUtils.isEmpty(hashResp.getResult())) {
            return new ResponseData<>(StringUtils.EMPTY, hashResp.getErrorCode(),
                hashResp.getErrorMessage());
        }
        if (!WeIdUtils.isPrivateKeyValid(weIdPrivateKey)) {
            return new ResponseData<>(StringUtils.EMPTY,
                ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        String privateKey = weIdPrivateKey.getPrivateKey();
        try {
            String signature = DataToolUtils.secp256k1Sign(hashValue, new BigInteger(privateKey));
            Long timestamp = DateUtils.getCurrentTimeStamp();

            if (processingMode == ProcessingMode.PERIODIC_AND_BATCH) {
                String[] args = new String[7];
                args[0] = hashValue;
                args[1] = signature;
                args[2] = log;
                args[3] = String.valueOf(timestamp);
                args[4] = customKey;
                args[5] = privateKey;
                args[6] = String.valueOf(this.groupId);
                String rawData = new StringBuffer()
                    .append(hashValue)
                    .append(signature)
                    .append(log)
                    .append(timestamp)
                    .append(customKey)
                    .append(WeIdUtils.getWeIdFromPrivateKey(privateKey))
                    .append(this.groupId).toString();
                String hash = DataToolUtils.sha3(rawData);
                String requestId = new BigInteger(hash.substring(2), 16).toString();
                boolean isSuccess = BatchTransactionUtils
                    .writeTransaction(requestId, "createEvidenceWithCustomKey", args,
                        StringUtils.EMPTY);
                if (isSuccess) {
                    return new ResponseData<>(hashValue, ErrorCode.SUCCESS);
                } else {
                    return new ResponseData<>(hashValue, ErrorCode.OFFLINE_EVIDENCE_SAVE_FAILED);
                }
            }

            return evidenceServiceEngine.createEvidenceWithCustomKey(
                hashValue,
                signature,
                log,
                timestamp,
                customKey,
                privateKey
            );
        } catch (Exception e) {
            logger.error("create evidence failed due to system error. ", e);
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR);
        }
    }

    /* (non-Javadoc)
     * @see com.webank.weid.rpc.EvidenceService#getEvidenceByCustomKey(java.lang.String)
     */
    @Override
    public ResponseData<EvidenceInfo> getEvidenceByCustomKey(String customKey) {
        if (!isChainStringLengthValid(customKey)) {
            return new ResponseData<>(null, ErrorCode.ON_CHAIN_STRING_TOO_LONG);
        }
        try {
            return evidenceServiceEngine.getInfoByCustomKey(customKey);
        } catch (Exception e) {
            logger.error("get evidence failed.", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR);
        }
    }

    private boolean isChainStringLengthValid(String string) {
        return string.length() < WeIdConstant.ON_CHAIN_STRING_LENGTH;
    }

    /**
     * Revoke an evidence - which can be un-revoked.
     *
     * @param object the object
     * @param weIdAuthentication the weid authentication
     * @return true if yes, false otherwise, with error codes
     */
    @Override
    public ResponseData<Boolean> revoke(Hashable object, WeIdAuthentication weIdAuthentication) {
        ResponseData<String> hashResp = getHashValue(object);
        if (StringUtils.isEmpty(hashResp.getResult())) {
            return new ResponseData<>(false, hashResp.getErrorCode(),
                hashResp.getErrorMessage());
        }
        if (weIdAuthentication == null
            || !WeIdUtils.isPrivateKeyValid(weIdAuthentication.getWeIdPrivateKey())) {
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        Long timestamp = DateUtils.getNoMillisecondTimeStamp();
        return evidenceServiceEngine.setAttribute(
            hashResp.getResult(),
            WeIdConstant.EVIDENCE_REVOKE_KEY,
            StringUtils.EMPTY,
            timestamp,
            weIdAuthentication.getWeIdPrivateKey().getPrivateKey()
        );
    }

    /**
     * Revoke an evidence - which can be un-revoked.
     *
     * @param object the object
     * @param weIdAuthentication the weid authentication
     * @return true if yes, false otherwise, with error codes
     */
    @Override
    public ResponseData<Boolean> unRevoke(Hashable object, WeIdAuthentication weIdAuthentication) {
        ResponseData<String> hashResp = getHashValue(object);
        if (StringUtils.isEmpty(hashResp.getResult())) {
            return new ResponseData<>(false, hashResp.getErrorCode(),
                hashResp.getErrorMessage());
        }
        if (weIdAuthentication == null
            || !WeIdUtils.isPrivateKeyValid(weIdAuthentication.getWeIdPrivateKey())) {
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        Long timestamp = DateUtils.getNoMillisecondTimeStamp();
        return evidenceServiceEngine.setAttribute(
            hashResp.getResult(),
            WeIdConstant.EVIDENCE_UNREVOKE_KEY,
            StringUtils.EMPTY,
            timestamp,
            weIdAuthentication.getWeIdPrivateKey().getPrivateKey()
        );
    }

    /**
     * Check whether this evidence is revoked by this WeID.
     *
     * @param evidenceInfo the EvidenceInfo
     * @param weId the signer WeID
     * @return true if revoked, false otherwise
     */
    @Override
    public ResponseData<Boolean> isRevoked(EvidenceInfo evidenceInfo, String weId) {
        if (evidenceInfo == null) {
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        Map<String, EvidenceSignInfo> evidenceSignInfos = evidenceInfo.getSignInfo();
        if (evidenceSignInfos == null || evidenceSignInfos.size() == 0
            || evidenceSignInfos.get(weId) == null) {
            return new ResponseData<>(false, ErrorCode.WEID_DOES_NOT_EXIST);
        }
        return new ResponseData<>(evidenceSignInfos.get(weId).getRevoked(), ErrorCode.SUCCESS);
    }
}
