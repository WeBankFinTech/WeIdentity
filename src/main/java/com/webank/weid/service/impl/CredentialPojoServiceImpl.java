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

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.github.fge.jsonschema.core.report.ProcessingReport;
import com.webank.wedpr.common.Utils;
import com.webank.wedpr.selectivedisclosure.CredentialTemplateEntity;
import com.webank.wedpr.selectivedisclosure.PredicateType;
import com.webank.wedpr.selectivedisclosure.UserClient;
import com.webank.wedpr.selectivedisclosure.UserResult;
import com.webank.wedpr.selectivedisclosure.VerifierClient;
import com.webank.wedpr.selectivedisclosure.VerifierResult;
import com.webank.wedpr.selectivedisclosure.proto.Predicate;
import com.webank.wedpr.selectivedisclosure.proto.VerificationRule;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.crypto.keypair.CryptoKeyPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.CredentialConstant;
import com.webank.weid.constant.CredentialConstant.CredentialProofType;
import com.webank.weid.constant.CredentialFieldDisclosureValue;
import com.webank.weid.constant.CredentialType;
import com.webank.weid.constant.DataDriverConstant;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.ParamKeyConstant;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.exception.DataTypeCastException;
import com.webank.weid.exception.WeIdBaseException;
import com.webank.weid.protocol.base.Challenge;
import com.webank.weid.protocol.base.ClaimPolicy;
import com.webank.weid.protocol.base.Cpt;
import com.webank.weid.protocol.base.CredentialPojo;
import com.webank.weid.protocol.base.PresentationE;
import com.webank.weid.protocol.base.PresentationPolicyE;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdDocument;
import com.webank.weid.protocol.base.WeIdPublicKey;
import com.webank.weid.protocol.cpt.Cpt101;
import com.webank.weid.protocol.cpt.Cpt111;
import com.webank.weid.protocol.request.CreateCredentialPojoArgs;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.rpc.CptService;
import com.webank.weid.rpc.CredentialPojoService;
import com.webank.weid.rpc.WeIdService;
import com.webank.weid.suite.api.persistence.PersistenceFactory;
import com.webank.weid.suite.api.persistence.inf.Persistence;
import com.webank.weid.suite.api.persistence.params.PersistenceType;
import com.webank.weid.suite.api.transportation.inf.PdfTransportation;
import com.webank.weid.suite.transportation.pdf.impl.PdfTransportationImpl;
import com.webank.weid.suite.transportation.pdf.protocol.PdfAttributeInfo;
import com.webank.weid.util.CredentialPojoUtils;
import com.webank.weid.util.CredentialUtils;
import com.webank.weid.util.DataToolUtils;
import com.webank.weid.util.DateUtils;
import com.webank.weid.util.JsonUtil;
import com.webank.weid.util.PropertyUtils;
import com.webank.weid.util.TimestampUtils;
import com.webank.weid.util.WeIdUtils;


/**
 * Service implementations for operations on CredentialPojo.
 *
 * @author tonychen 2019年4月17日
 */
public class CredentialPojoServiceImpl implements CredentialPojoService {

    private static final Logger logger = LoggerFactory.getLogger(CredentialPojoServiceImpl.class);
    private static final String NOT_DISCLOSED =
        CredentialFieldDisclosureValue.NOT_DISCLOSED.getStatus().toString();
    private static final String DISCLOSED =
        CredentialFieldDisclosureValue.DISCLOSED.getStatus().toString();
    private static final String EXISTED =
        CredentialFieldDisclosureValue.EXISTED.getStatus().toString();
    private static WeIdService weIdService;
    private static CptService cptService;
    private static Persistence dataDriver;
    private static PersistenceType persistenceType;
    private static PdfTransportation pdfTransportation;

    private static Persistence getDataDriver() {
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

    private static WeIdService getWeIdService() {
        if (weIdService == null) {
            weIdService = new WeIdServiceImpl();
        }
        return weIdService;
    }

    private static CptService getCptService() {
        if (cptService == null) {
            cptService = new CptServiceImpl();
        }
        return cptService;
    }

    private static PdfTransportation getPdfTransportation() {
        if (pdfTransportation == null) {
            pdfTransportation = new PdfTransportationImpl();
        }
        return pdfTransportation;
    }

    /**
     * Salt generator. Automatically fillin the map structure in a recursive manner.
     *
     * @param map the passed map (claim, salt or alike)
     * @param fixed fixed value if required to use
     */
    public static void generateSalt(Map<String, Object> map, Object fixed) {
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof Map) {
                generateSalt((HashMap) value, fixed);
            } else if (value instanceof List) {
                boolean isMapOrList = generateSaltFromList((ArrayList<Object>) value, fixed);
                if (!isMapOrList) {
                    if (fixed == null) {
                        addSalt(entry);
                    } else {
                        entry.setValue(fixed);
                    }
                }
            } else {
                if (fixed == null) {
                    addSalt(entry);
                } else {
                    entry.setValue(fixed);
                }
            }
        }
    }

    private static void addSalt(Map.Entry<String, Object> entry) {
        String salt = DataToolUtils.getRandomSalt();
        entry.setValue(salt);
    }

    private static boolean generateSaltFromList(List<Object> objList, Object fixed) {
        List<Object> list = (List<Object>) objList;
        for (Object obj : list) {
            if (obj instanceof Map) {
                generateSalt((HashMap) obj, fixed);
            } else if (obj instanceof List) {
                boolean result = generateSaltFromList((ArrayList<Object>) obj, fixed);
                if (!result) {
                    return result;
                }
            } else {
                return false;
            }
        }
        return true;
    }

    /**
     * 校验claim、salt和disclosureMap的格式是否一致.
     */
    private static boolean validCredentialMapArgs(Map<String, Object> claim,
        Map<String, Object> salt, Map<String, Object> disclosureMap) {

        //检查是否为空
        if (claim == null || salt == null || disclosureMap == null) {
            return false;
        }

        //检查每个map里的key个数是否相同
        if (!claim.keySet().equals(salt.keySet())) {
            return false;
        }

        //检查key值是否一致
        for (Map.Entry<String, Object> entry : disclosureMap.entrySet()) {
            String k = entry.getKey();
            Object v = entry.getValue();
            //如果disclosureMap中的key在claim中没有则返回false
            if (!claim.containsKey(k)) {
                return false;
            }
            Object saltV = salt.get(k);
            Object claimV = claim.get(k);
            if (v instanceof Map) {
                //递归检查
                if (!validCredentialMapArgs((HashMap) claimV, (HashMap) saltV, (HashMap) v)) {
                    return false;
                }
            } else if (v instanceof List) {
                if (!validCredentialListArgs(
                    (ArrayList<Object>) claimV,
                    (ArrayList<Object>) saltV,
                    (ArrayList<Object>) v
                )) {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean validCredentialListArgs(
        List<Object> claimList,
        List<Object> saltList,
        List<Object> disclosureList) {
        //检查是否为空
        if (claimList == null || saltList == null || disclosureList == null) {
            return false;
        }
        if (claimList.size() != saltList.size()) {
            return false;
        }
        for (int i = 0; i < disclosureList.size(); i++) {
            Object disclosureObj = disclosureList.get(i);
            Object claimObj = claimList.get(i);
            Object saltObj = saltList.get(i);
            if (disclosureObj instanceof Map) {
                boolean result =
                    validCredentialListArgs(
                        claimList,
                        saltList,
                        (HashMap) disclosureObj
                    );
                if (!result) {
                    return result;
                }
            } else if (disclosureObj instanceof List) {
                boolean result =
                    validCredentialListArgs(
                        (ArrayList<Object>) claimObj,
                        (ArrayList<Object>) saltObj,
                        (ArrayList<Object>) disclosureObj
                    );
                if (!result) {
                    return result;
                }
            }
        }
        return true;
    }

    private static boolean validCredentialListArgs(
        List<Object> claimList,
        List<Object> saltList,
        Map<String, Object> disclosure
    ) {

        if (claimList == null || saltList == null || saltList.size() != claimList.size()) {
            return false;
        }

        for (int i = 0; i < claimList.size(); i++) {
            Object claim = claimList.get(i);
            Object salt = saltList.get(i);
            boolean result = validCredentialMapArgs((HashMap) claim, (HashMap) salt, disclosure);
            if (!result) {
                return result;
            }
        }
        return true;
    }

    //向policy中补充缺失的key
    private static void addKeyToPolicy(
        Map<String, Object> disclosureMap,
        Map<String, Object> claimMap
    ) {
        for (Map.Entry<String, Object> entry : claimMap.entrySet()) {
            String claimK = entry.getKey();
            Object claimV = entry.getValue();
            if (claimV instanceof Map) {
                HashMap claimHashMap = (HashMap) claimV;
                if (!disclosureMap.containsKey(claimK)) {
                    disclosureMap.put(claimK, new HashMap());
                }
                HashMap disclosureHashMap = (HashMap) disclosureMap.get(claimK);
                addKeyToPolicy(disclosureHashMap, claimHashMap);
            } else if (claimV instanceof List) {
                ArrayList claimList = (ArrayList) claimV;
                //判断claimList中是否包含Map结构，还是单一结构
                boolean isSampleList = isSampleListForClaim(claimList);
                if (isSampleList) {
                    if (!disclosureMap.containsKey(claimK)) {
                        disclosureMap.put(claimK, Integer.parseInt(NOT_DISCLOSED));
                    }
                } else {
                    if (!disclosureMap.containsKey(claimK)) {
                        disclosureMap.put(claimK, new ArrayList());
                    }
                    ArrayList disclosureList = (ArrayList) disclosureMap.get(claimK);
                    addKeyToPolicyList(disclosureList, claimList);
                }
            } else {
                if (!disclosureMap.containsKey(claimK)) {
                    disclosureMap.put(claimK, Integer.parseInt(NOT_DISCLOSED));
                }
            }
        }
    }

    private static void addKeyToPolicyList(
        ArrayList disclosureList,
        ArrayList claimList
    ) {
        for (int i = 0; i < claimList.size(); i++) {
            Object claimObj = claimList.get(i);
            if (claimObj instanceof Map) {
                Object disclosureObj = disclosureList.size() == 0 ? null : disclosureList.get(0);
                if (disclosureObj == null) {
                    disclosureList.add(new HashMap());
                }
                HashMap disclosureHashMap = (HashMap) disclosureList.get(0);
                addKeyToPolicy(disclosureHashMap, (HashMap) claimObj);
                break;
            } else if (claimObj instanceof List) {
                Object disclosureObj = disclosureList.get(i);
                if (disclosureObj == null) {
                    disclosureList.add(new ArrayList());
                }
                ArrayList disclosureArrayList = (ArrayList) disclosureList.get(i);
                addKeyToPolicyList(disclosureArrayList, (ArrayList) claimObj);
            }
        }
    }

    private static boolean isSampleListForClaim(ArrayList claimList) {
        if (CollectionUtils.isEmpty(claimList)) {
            return true;
        }
        Object claimObj = claimList.get(0);
        if (claimObj instanceof Map) {
            return false;
        }
        if (claimObj instanceof List) {
            return isSampleListForClaim((ArrayList) claimObj);
        }
        return true;
    }

    private static void addSelectSalt(
        Map<String, Object> disclosureMap,
        Map<String, Object> saltMap,
        Map<String, Object> claim,
        boolean isZkp
    ) {
        for (Map.Entry<String, Object> entry : disclosureMap.entrySet()) {
            String disclosureKey = entry.getKey();
            Object value = entry.getValue();
            Object saltV = saltMap.get(disclosureKey);
            Object claimV = claim.get(disclosureKey);
            if (value == null) {
                throw new WeIdBaseException(ErrorCode.CREDENTIAL_POLICY_DISCLOSUREVALUE_ILLEGAL);
            } else if ((value instanceof Map) && (claimV instanceof Map)) {
                addSelectSalt((HashMap) value, (HashMap) saltV, (HashMap) claimV, isZkp);
            } else if (value instanceof List) {
                addSaltForList(
                    (ArrayList<Object>) value,
                    (ArrayList<Object>) saltV,
                    (ArrayList<Object>) claimV,
                    isZkp
                );
            } else {
                addHashToClaim(saltMap, claim, disclosureKey, value, saltV, claimV, isZkp);
            }
        }
    }

    private static void addHashToClaim(
        Map<String, Object> saltMap,
        Map<String, Object> claim,
        String disclosureKey,
        Object value,
        Object saltV,
        Object claimV,
        boolean isZkp
    ) {

        if (isZkp) {
            if ((value instanceof Map) || !(((Integer) value).equals(Integer.parseInt(DISCLOSED))
                && claim.containsKey(disclosureKey))) {
                String hash =
                    CredentialPojoUtils.getFieldSaltHash(
                        String.valueOf(claimV),
                        String.valueOf(saltV)
                    );
                claim.put(disclosureKey, hash);
            }
        } else {

            if (((Integer) value).equals(Integer.parseInt(NOT_DISCLOSED))
                && claim.containsKey(disclosureKey)) {
                saltMap.put(disclosureKey, NOT_DISCLOSED);
                String hash =
                    CredentialPojoUtils.getFieldSaltHash(
                        String.valueOf(claimV),
                        String.valueOf(saltV)
                    );
                claim.put(disclosureKey, hash);
            }
        }
    }

    private static void addSaltForList(
        List<Object> disclosures,
        List<Object> salt,
        List<Object> claim,
        boolean isZkp) {
        for (int i = 0; claim != null && i < disclosures.size(); i++) {
            Object disclosureObj = disclosures.get(i);
            Object claimObj = claim.get(i);
            Object saltObj = salt.get(i);
            if (disclosureObj instanceof Map) {
                addSaltForList((HashMap) disclosureObj, salt, claim, isZkp);
            } else if (disclosureObj instanceof List) {
                addSaltForList(
                    (ArrayList<Object>) disclosureObj,
                    (ArrayList<Object>) saltObj,
                    (ArrayList<Object>) claimObj,
                    isZkp
                );
            }
        }
    }

    private static void addSaltForList(
        Map<String, Object> disclosures,
        List<Object> salt,
        List<Object> claim,
        boolean isZkp
    ) {
        for (int i = 0; claim != null && i < claim.size(); i++) {
            Object claimObj = claim.get(i);
            Object saltObj = salt.get(i);
            addSelectSalt(disclosures, (HashMap) saltObj, (HashMap) claimObj, isZkp);
        }
    }

    private static ErrorCode verifyContent(
        CredentialPojo credential,
        String publicKey,
        boolean offLine,
        String weIdPublicKeyId
    ) {
        ErrorCode errorCode;
        try {
            errorCode = verifyContentInner(credential, publicKey, offLine, weIdPublicKeyId);
        } catch (WeIdBaseException ex) {
            logger.error("[verifyContent] verify credential has exception.", ex);
            return ex.getErrorCode();
        }
        // System CPT business related check
        if (errorCode == ErrorCode.SUCCESS
            && CredentialPojoUtils.isSystemCptId(credential.getCptId())) {
            errorCode = verifySystemCptClaimInner(credential);
        }
        return errorCode;
    }

    private static ErrorCode verifySystemCptClaimInner(CredentialPojo credential) {
        if (credential.getCptId().intValue() == CredentialConstant.EMBEDDED_TIMESTAMP_CPT) {
            return verifyTimestampClaim(credential);
        }
        if (credential.getCptId().intValue() == CredentialConstant.AUTHORIZATION_CPT) {
            return verifyAuthClaim(credential);
        }
        return ErrorCode.SUCCESS;
    }

    private static ErrorCode verifyAuthClaim(CredentialPojo credential) {
        Cpt101 authInfo;
        try {
            authInfo = DataToolUtils.mapToObj(credential.getClaim(), Cpt101.class);
        } catch (Exception e) {
            logger.error("Failed to deserialize authorization information.");
            return ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL;
        }
        ErrorCode errorCode = verifyAuthInfo(authInfo);
        if (errorCode != ErrorCode.SUCCESS) {
            return errorCode;
        }
        // Extra check 1: cannot authorize other WeID's resources
        String issuerWeId = credential.getIssuer();
        if (!issuerWeId.equalsIgnoreCase(authInfo.getFromWeId())) {
            return ErrorCode.AUTHORIZATION_CANNOT_AUTHORIZE_OTHER_WEID_RESOURCE;
        }
        // TODO Extra check 2: check service url endpoint exposed or not?
        // Need getWeIdDocument() check
        return ErrorCode.SUCCESS;
    }

    private static ErrorCode verifyTimestampClaim(CredentialPojo credential) {
        Map<String, Object> claim = credential.getClaim();
        if (((String) claim.get("timestampAuthority"))
            .contains(TimestampUtils.WESIGN_AUTHORITY_NAME)) {
            String hashValue = (String) claim.get("claimHash");
            String authoritySignature = (String) claim.get("authoritySignature");
            Long timestamp = (long) claim.get("timestamp");
            ResponseData<Boolean> resp =
                TimestampUtils.verifyWeSignTimestamp(hashValue, authoritySignature, timestamp);
            if (!resp.getResult()) {
                return ErrorCode.getTypeByErrorCode(resp.getErrorCode());
            }
        }
        return ErrorCode.SUCCESS;
    }

    private static ErrorCode verifyContentInner(
        CredentialPojo credential,
        String publicKey,
        boolean offline,
        String weIdPublicKeyId
    ) {
        ErrorCode checkResp = CredentialPojoUtils.isCredentialPojoValid(credential);
        if (ErrorCode.SUCCESS.getCode() != checkResp.getCode()) {
            return checkResp;
        }
        if (credential.getCptId() == CredentialConstant.CREDENTIAL_EMBEDDED_SIGNATURE_CPT
            .intValue()) {
            logger.error("Embedded Credential is obsoleted. Please use embedded Credential Pojo.");
            return ErrorCode.CPT_ID_ILLEGAL;
        }
        if (credential.getCptId() == CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT
            .intValue() || credential.getCptId() == CredentialConstant.EMBEDDED_TIMESTAMP_CPT
            .intValue()) {
            // This is a multi-signed Credential. We firstly verify itself (i.e. external check)
            ErrorCode errorCode = verifySingleSignedCredential(
                credential, publicKey, offline, weIdPublicKeyId);
            if (errorCode != ErrorCode.SUCCESS) {
                return errorCode;
            }
            // Then, we verify its list members one-by-one
            List<Object> innerCredentialList;
            try {
                if (credential.getClaim().get("credentialList") instanceof String) {
                    // For selectively-disclosed credential, stop here. External check is enough.
                    return ErrorCode.SUCCESS;
                } else {
                    innerCredentialList = (ArrayList) credential.getClaim().get("credentialList");
                }
            } catch (Exception e) {
                logger.error("the credential claim data illegal.", e);
                return ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL;
            }
            for (Object innerCredentialObject : innerCredentialList) {
                // PublicKey can only be used in the passed-external check, so pass-in null key
                try {
                    CredentialPojo innerCredential;
                    if (!(innerCredentialObject instanceof CredentialPojo)) {
                        Map<String, Object> map = (Map<String, Object>) innerCredentialObject;
                        innerCredential = DataToolUtils
                            .mapToObj(map, CredentialPojo.class);
                    } else {
                        innerCredential = (CredentialPojo) innerCredentialObject;
                    }
                    errorCode = verifyContentInner(
                        innerCredential, null, offline, weIdPublicKeyId);
                    if (errorCode != ErrorCode.SUCCESS) {
                        return errorCode;
                    }
                } catch (Exception e) {
                    logger.error("Failed to convert credentialPojo to object.", e);
                    return ErrorCode.ILLEGAL_INPUT;
                }
            }
            return ErrorCode.SUCCESS;
        }
        return verifySingleSignedCredential(credential, publicKey, offline, weIdPublicKeyId);
    }

    private static ErrorCode verifySingleSignedCredential(
        CredentialPojo credential,
        String publicKey,
        boolean offline,
        String weIdPublicKeyId
    ) {
        ErrorCode errorCode = verifyCptFormat(
            credential.getCptId(),
            credential.getClaim(),
            CredentialPojoUtils.isSelectivelyDisclosed(credential.getSalt()),
            offline
        );
        if (ErrorCode.SUCCESS.getCode() != errorCode.getCode()) {
            return errorCode;
        }
        Map<String, Object> salt = credential.getSalt();
        String rawData;
        if (CredentialPojoUtils.isEmbeddedCredential(credential)) {
            List<Object> objList = (ArrayList<Object>) credential.getClaim().get("credentialList");
            List<CredentialPojo> credentialList = new ArrayList<>();
            try {
                for (Object obj : objList) {
                    if (obj instanceof CredentialPojo) {
                        credentialList.add((CredentialPojo) obj);
                    } else {
                        credentialList.add(DataToolUtils
                            .mapToObj((HashMap<String, Object>) obj, CredentialPojo.class));
                    }
                }
            } catch (Exception e) {
                logger.error("Failed to convert credentialPojo: " + e.getMessage(), e);
                return ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL;
            }
            rawData = CredentialPojoUtils.getEmbeddedCredentialThumbprintWithoutSig(credentialList);
        } else {
            rawData = CredentialPojoUtils
                .getCredentialThumbprintWithoutSig(credential, salt, null);
        }
        String issuerWeid = credential.getIssuer();
        if (StringUtils.isEmpty(publicKey)) {
            // Fetch public key from chain
            ResponseData<WeIdDocument> innerResponseData =
                getWeIdService().getWeIdDocument(issuerWeid);
            if (innerResponseData.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
                logger.error(
                    "Error occurred when fetching WeIdentity DID document for: {}, msg: {}",
                    issuerWeid, innerResponseData.getErrorMessage());
                return ErrorCode.getTypeByErrorCode(innerResponseData.getErrorCode());
            } else {
                WeIdDocument weIdDocument = innerResponseData.getResult();
                errorCode = DataToolUtils.verifySecp256k1SignatureFromWeId(
                    rawData, credential.getSignature(), weIdDocument, weIdPublicKeyId);
                return errorCode;
            }
        } else {
            boolean result;
            try {
                result = DataToolUtils.verifySecp256k1Signature(rawData,
                    credential.getSignature(), new BigInteger(publicKey));

            } catch (Exception e) {
                logger.error("[verifyContent] verify signature fail.", e);
                return ErrorCode.CREDENTIAL_SIGNATURE_BROKEN;
            }
            if (!result) {
                return ErrorCode.CREDENTIAL_VERIFY_FAIL;
            }
            return ErrorCode.SUCCESS;
        }
    }


    private static ErrorCode verifyCptFormat(
        Integer cptId, Map<String, Object> claim,
        boolean isSelectivelyDisclosed,
        boolean offline
    ) {
        if (cptId == CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT.intValue()) {
            if (!claim.containsKey("credentialList")) {
                return ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL;
            } else {
                return ErrorCode.SUCCESS;
            }
        }
        if (cptId == CredentialConstant.EMBEDDED_TIMESTAMP_CPT.intValue()) {
            if (claim.containsKey("credentialList") && claim.containsKey("claimHash")
                && claim.containsKey("timestampAuthority") && claim.containsKey("timestamp")
                && claim.containsKey("authoritySignature")) {
                return ErrorCode.SUCCESS;
            } else {
                return ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL;
            }
        }
        try {
            if (offline) {
                return ErrorCode.SUCCESS;
            }
            String claimStr = DataToolUtils.serialize(claim);
            Cpt cpt = getCptService().queryCpt(cptId).getResult();
            if (cpt == null) {
                logger.error(ErrorCode.CREDENTIAL_CPT_NOT_EXISTS.getCodeDesc());
                return ErrorCode.CREDENTIAL_CPT_NOT_EXISTS;
            }
            //String cptJsonSchema = JsonUtil.objToJsonStr(cpt.getCptJsonSchema());
            String cptJsonSchema = DataToolUtils.serialize(cpt.getCptJsonSchema());

            if (!DataToolUtils.isCptJsonSchemaValid(cptJsonSchema)) {
                logger.error(ErrorCode.CPT_JSON_SCHEMA_INVALID.getCodeDesc());
                return ErrorCode.CPT_JSON_SCHEMA_INVALID;
            }
            if (!isSelectivelyDisclosed) {
                ProcessingReport checkRes = DataToolUtils.checkJsonVersusSchema(
                    claimStr, cptJsonSchema);
                if (!checkRes.isSuccess()) {
                    logger.error(ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL.getCodeDesc());
                    return ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL;
                }
            }
            return ErrorCode.SUCCESS;
        } catch (Exception e) {
            logger.error(
                "Generic error occurred during verify cpt format when verifyCredential: ", e);
            return ErrorCode.CREDENTIAL_ERROR;
        }
    }

    private static ResponseData<Boolean> verifyZkpCredential(CredentialPojo credential) {

        Map<String, Object> proof = credential.getProof();
        String encodedVerificationRule = (String) proof
            .get(ParamKeyConstant.PROOF_ENCODEDVERIFICATIONRULE);
        String verificationRequest = (String) proof.get(ParamKeyConstant.PROOF_VERIFICATIONREQUEST);
        VerifierResult verifierResult =
            VerifierClient.verifyProof(encodedVerificationRule, verificationRequest);
        if (verifierResult.wedprErrorMessage == null) {
            return new ResponseData<Boolean>(true, ErrorCode.SUCCESS);
        }

        return new ResponseData<Boolean>(false, ErrorCode.CREDENTIAL_VERIFY_FAIL);
    }

    private static Boolean isZkpCredential(CredentialPojo credential) {

        List<String> types = credential.getType();
        for (String type : types) {
            if (StringUtils.equals(type, CredentialType.ZKP.getName())) {
                return true;
            }
        }
        return false;
    }

    /**
     * user build credential Info map and makeCredential.
     */
    private static UserResult makeCredential(
        CredentialPojo preCredential,
        String claimJson,
        Integer cptId,
        WeIdAuthentication weIdAuthentication) {

        Map<String, String> credentialInfoMap = buildCredentialInfo(preCredential, claimJson);

        ResponseData<CredentialTemplateEntity> res = getCptService().queryCredentialTemplate(cptId);
        CredentialTemplateEntity credentialTemplate = res.getResult();

        UserResult userResult = UserClient.makeCredential(credentialInfoMap, credentialTemplate);

        // masterSecret is saved by User
        String masterSecret = userResult.masterSecret;
        String credentialSecretsBlindingFactors = userResult.credentialSecretsBlindingFactors;

        Map<String, String> userCredentialInfo = new HashMap<>();
        userCredentialInfo.put(ParamKeyConstant.MASTER_SECRET, masterSecret);
        userCredentialInfo.put(ParamKeyConstant.BLINDING_FACTORS, credentialSecretsBlindingFactors);
        String json = DataToolUtils.serialize(userCredentialInfo);
        String id = new StringBuffer().append(weIdAuthentication.getWeId()).append("_")
            .append(cptId).toString();
        //String id=(String)preCredential.getClaim().get(CredentialConstant.CREDENTIAL_META_KEY_ID);

        //save masterSecret and credentialSecretsBlindingFactors to persistence.
        ResponseData<Integer> dbResp = getDataDriver()
            .addOrUpdate(DataDriverConstant.DOMAIN_USER_MASTER_SECRET, id, json);
        if (dbResp.getErrorCode().intValue() != ErrorCode.SUCCESS.getCode()) {
            logger.error(
                "[makeCredential] save masterSecret and blindingFactors to db failed.");
            return null;
        }

        return userResult;
    }

    /**
     * build credentialInfoMap from pre-credential and claim sent by issuer.
     */
    private static Map<String, String> buildCredentialInfo(CredentialPojo preCredential,
        String claimJson) {

        CredentialPojo tempCredential = DataToolUtils.clone(preCredential);
        Map<String, Object> claim = preCredential.getClaim();
        Map<String, String> credentialInfo = new HashMap<String, String>();
        Map<String, String> newCredentialInfo = new HashMap<String, String>();
        try {
            Map<String, Object> claimMap = DataToolUtils.deserialize(claimJson, HashMap.class);
            tempCredential.setClaim(claimMap);
            tempCredential.setContext(
                String.valueOf(claim.get(CredentialConstant.CREDENTIAL_META_KEY_CONTEXT)));
            tempCredential
                .setCptId((Integer) claim.get(CredentialConstant.CREDENTIAL_META_KEY_CPTID));
            Long newExpirationDate =
                DateUtils.convertToNoMillisecondTimeStamp(
                    (Long) (claim.get(CredentialConstant.CREDENTIAL_META_KEY_EXPIRATIONDATE)));
            tempCredential.setExpirationDate(newExpirationDate);
            tempCredential
                .setId(String.valueOf(claim.get(CredentialConstant.CREDENTIAL_META_KEY_ID)));
            Long newIssuanceDate =
                DateUtils.convertToNoMillisecondTimeStamp(
                    (Long) (claim.get(CredentialConstant.CREDENTIAL_META_KEY_ISSUANCEDATE)));
            tempCredential.setIssuanceDate(newIssuanceDate);
            tempCredential.setIssuer(
                String.valueOf(claim.get(CredentialConstant.CREDENTIAL_META_KEY_ISSUER)));
            credentialInfo = JsonUtil.credentialToMonolayer(tempCredential);
            for (Map.Entry<String, String> entry : credentialInfo.entrySet()) {
                newCredentialInfo.put(entry.getKey(), String.valueOf(entry.getValue()));
            }
        } catch (IOException e) {
            logger.error("[buildCredentialInfo] build credential info map failed.", e);
        }
        return newCredentialInfo;
    }

    private static void processZkpPolicy(
        ClaimPolicy claimPolicy,
        List<String> revealedAttributeList,
        List<Predicate> predicateList) {

        String policyJson = null;
        try {
            policyJson = JsonUtil.claimPolicyToMonolayer(claimPolicy);
        } catch (IOException e) {
            e.printStackTrace();
        }
        Map<String, Object> disclosureMap = DataToolUtils
            .deserialize(policyJson, HashMap.class);
        for (Map.Entry<String, Object> entry : disclosureMap.entrySet()) {

            String key = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof Map) {
                processExpression(key, (HashMap) value, predicateList);
            } else if (value instanceof Integer) {
                processBaseValue(key, String.valueOf(value), revealedAttributeList);
            } else if (value instanceof String) {
                processBaseValue(key, (String) value, revealedAttributeList);
            } else {
                return;
            }
        }

    }

    private static void processExpression(
        String key,
        Map<String, Object> expression,
        List<Predicate> predicateList) {

        for (Map.Entry<String, Object> entry : expression.entrySet()) {

            String predicateKey = entry.getKey();
            Object predicateValue = entry.getValue();
            PredicateType predicateType = getPredicateType(predicateKey);
            Predicate predicate = Utils.makePredicate(key, predicateType, (Integer) predicateValue);
            predicateList.add(predicate);
        }
    }

    private static void processBaseValue(
        String key,
        String value,
        List<String> revealedAttributeList) {
        if (StringUtils.equals(value, DISCLOSED)) {
            revealedAttributeList.add(key);
        }
    }

    private static PredicateType getPredicateType(String predicate) {

        switch (predicate) {
            case "EQ":
                return PredicateType.EQ;
            case "GE":
                return PredicateType.GE;
            case "GT":
                return PredicateType.GT;
            case "LE":
                return PredicateType.LE;
            case "LT":
                return PredicateType.LT;
            default:
                return null;

        }
    }

    private static ResponseData<Boolean> verifyLiteCredential(
        CredentialPojo credential,
        String publicKey,
        String weIdPublicKeyId) {
        // Lite Credential only contains limited areas (others truncated)
        if (credential.getCptId() == null || credential.getCptId().intValue() < 0) {
            return new ResponseData<>(false, ErrorCode.CPT_ID_ILLEGAL);
        }
        if (!WeIdUtils.isWeIdValid(credential.getIssuer())) {
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_ISSUER_INVALID);
        }
        if (credential.getClaim() == null || credential.getClaim().size() == 0) {
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_CLAIM_NOT_EXISTS);
        }
        if (credential.getProof() == null || StringUtils.isEmpty(credential.getSignature())) {
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_SIGNATURE_NOT_EXISTS);
        }
        String rawData = CredentialPojoUtils.getLiteCredentialThumbprintWithoutSig(credential);

        // Using provided public key to verify signature
        if (!StringUtils.isBlank(publicKey)) {
            boolean result;
            try {
                // For Lite CredentialPojo, we begin to use Secp256k1 verify to fit external type
                result = DataToolUtils.verifySecp256k1Signature(rawData, credential.getSignature(),
                    new BigInteger(publicKey));
            } catch (Exception e) {
                logger.error("[verifyContent] verify signature fail.", e);
                return new ResponseData<Boolean>(false, ErrorCode.CREDENTIAL_SIGNATURE_BROKEN);
            }
            if (!result) {
                return new ResponseData<Boolean>(false, ErrorCode.CREDENTIAL_VERIFY_FAIL);
            }
            return new ResponseData<Boolean>(true, ErrorCode.SUCCESS);
        }

        // No existing public key hence go chain
        String issuerWeid = credential.getIssuer();
        // Fetch public key from chain
        ResponseData<WeIdDocument> innerResponseData =
            getWeIdService().getWeIdDocument(issuerWeid);
        if (innerResponseData.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
            logger.error(
                "Error occurred when fetching WeIdentity DID document for: {}, msg: {}",
                issuerWeid, innerResponseData.getErrorMessage());
            return new ResponseData<Boolean>(false,
                ErrorCode.getTypeByErrorCode(innerResponseData.getErrorCode()));
        } else {
            WeIdDocument weIdDocument = innerResponseData.getResult();
            ErrorCode verifyErrorCode = DataToolUtils.verifySecp256k1SignatureFromWeId(
                rawData, credential.getSignature(), weIdDocument, weIdPublicKeyId);
            if (verifyErrorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
                return new ResponseData<Boolean>(false, verifyErrorCode);
            }
            return new ResponseData<Boolean>(true, ErrorCode.SUCCESS);

        }
    }

    /**
     * Verify the authorization info in an authorization token credential.
     *
     * @param authInfo the auth info in CPT101 format
     * @return success if valid, specific error codes otherwise
     */
    public static ErrorCode verifyAuthInfo(Cpt101 authInfo) {
        if (authInfo == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }

        String serviceUrl = authInfo.getServiceUrl();
        String resourceId = authInfo.getResourceId();
        Long duration = authInfo.getDuration();
        if (!CredentialUtils.isValidUuid(resourceId)) {
            logger.error("Resource ID illegal: is not a valid UUID.");
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (!DataToolUtils.isValidEndpointUrl(serviceUrl)) {
            logger.error("Service URL illegal.");
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (duration < 0) {
            logger.error("Auth token duration of validity illegal: already expired.");
            return ErrorCode.CREDENTIAL_EXPIRE_DATE_ILLEGAL;
        }

        String fromWeId = authInfo.getFromWeId();
        String toWeId = authInfo.getToWeId();
        if (fromWeId.equalsIgnoreCase(toWeId)) {
            logger.error("FromWeId and ToWeId must be different.");
            return ErrorCode.AUTHORIZATION_FROM_TO_MUST_BE_DIFFERENT;
        }
        ResponseData<Boolean> existResp = getWeIdService().isWeIdExist(fromWeId);
        if (!existResp.getResult()) {
            logger.error("From WeID illegal: {}", existResp.getErrorMessage());
            return ErrorCode.getTypeByErrorCode(existResp.getErrorCode());
        }
        existResp = getWeIdService().isWeIdExist(toWeId);
        if (!existResp.getResult()) {
            logger.error("To WeID illegal: {}", existResp.getErrorMessage());
            return ErrorCode.getTypeByErrorCode(existResp.getErrorCode());
        }
        return ErrorCode.SUCCESS;
    }

    /* (non-Javadoc)
     * @see com.webank.weid.rpc.CredentialPojoService#createCredential(
     *          com.webank.weid.protocol.request.CreateCredentialPojoArgs
     *      )
     */
    @Override
    public ResponseData<CredentialPojo> createCredential(CreateCredentialPojoArgs args) {

        try {
            ErrorCode innerResponseData =
                CredentialPojoUtils.isCreateCredentialPojoArgsValid(args);
            if (ErrorCode.SUCCESS.getCode() != innerResponseData.getCode()) {
                logger.error("Create Credential Args illegal: {}",
                    innerResponseData.getCodeDesc());
                return new ResponseData<>(null, innerResponseData);
            }
            CredentialPojo result = new CredentialPojo();
            String context = CredentialUtils.getDefaultCredentialContext();
            result.setContext(context);
            if (StringUtils.isBlank(args.getId())) {
                result.setId(UUID.randomUUID().toString());
            } else {
                result.setId(args.getId());
            }
            result.setCptId(args.getCptId());
            Long issuanceDate = args.getIssuanceDate();
            if (issuanceDate == null) {
                result.setIssuanceDate(DateUtils.getNoMillisecondTimeStamp());
            } else {
                Long newIssuanceDate =
                    DateUtils.convertToNoMillisecondTimeStamp(args.getIssuanceDate());
                if (newIssuanceDate == null) {
                    logger.error("Create Credential Args illegal.");
                    return new ResponseData<>(null, ErrorCode.CREDENTIAL_ISSUANCE_DATE_ILLEGAL);
                } else {
                    result.setIssuanceDate(newIssuanceDate);
                }
            }
            // Comment these lines out since we now support multi-public-keys in WeID document
            // if (!WeIdUtils.validatePrivateKeyWeIdMatches(
            //     args.getWeIdAuthentication().getWeIdPrivateKey(),
            //     args.getIssuer())) {
            //     logger.error("Create Credential, private key does not match the current weid.");
            //     return new ResponseData<>(null, ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH);
            // }
            result.setIssuer(args.getIssuer());
            Long newExpirationDate =
                DateUtils.convertToNoMillisecondTimeStamp(args.getExpirationDate());
            if (newExpirationDate == null) {
                logger.error("Create Credential Args illegal.");
                return new ResponseData<>(null, ErrorCode.CREDENTIAL_EXPIRE_DATE_ILLEGAL);
            } else {
                result.setExpirationDate(newExpirationDate);
            }
            result.addType(CredentialConstant.DEFAULT_CREDENTIAL_TYPE);
            result.addType(args.getType().getName());

            Object claimObject = args.getClaim();
            String claimStr = null;
            if (!(claimObject instanceof String)) {
                claimStr = DataToolUtils.serialize(claimObject);
            } else {
                claimStr = (String) claimObject;
            }

            HashMap<String, Object> claimMap = DataToolUtils.deserialize(claimStr, HashMap.class);
            result.setClaim(claimMap);

            String privateKey = args.getWeIdAuthentication().getWeIdPrivateKey().getPrivateKey();
            if (StringUtils.equals(args.getType().getName(), CredentialType.LITE1.getName())) {
                return createLiteCredential(result, privateKey);
            }

            Map<String, Object> saltMap = DataToolUtils.clone(claimMap);
            generateSalt(saltMap, null);
            String rawData = CredentialPojoUtils
                .getCredentialThumbprintWithoutSig(result, saltMap, null);

            String signature = DataToolUtils.secp256k1Sign(rawData, new BigInteger(privateKey));

            result.putProofValue(ParamKeyConstant.PROOF_CREATED, result.getIssuanceDate());

            String weIdPublicKeyId = args.getWeIdAuthentication().getWeIdPublicKeyId();
            result.putProofValue(ParamKeyConstant.PROOF_CREATOR, weIdPublicKeyId);

            String proofType = CredentialProofType.ECDSA.getTypeName();
            result.putProofValue(ParamKeyConstant.PROOF_TYPE, proofType);
            result.putProofValue(ParamKeyConstant.PROOF_SIGNATURE, signature);
            result.setSalt(saltMap);
            ResponseData<CredentialPojo> responseData = new ResponseData<>(
                result,
                ErrorCode.SUCCESS
            );

            return responseData;
        } catch (Exception e) {
            logger.error("Generate Credential failed due to system error. ", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_ERROR);
        }
    }

    private ResponseData<CredentialPojo> createLiteCredential(CredentialPojo credentialPojo,
        String privateKey) {

        String rawData = CredentialPojoUtils.getLiteCredentialThumbprintWithoutSig(credentialPojo);

        // For Lite CredentialPojo, we begin to use Secp256k1 format signature to fit external type
        String signature = DataToolUtils.secp256k1Sign(rawData, new BigInteger(privateKey, 10));

        String proofType = CredentialProofType.ECDSA.getTypeName();
        credentialPojo.putProofValue(ParamKeyConstant.PROOF_TYPE, proofType);
        credentialPojo.putProofValue(ParamKeyConstant.PROOF_SIGNATURE, signature);
        ResponseData<CredentialPojo> responseData = new ResponseData<>(
            credentialPojo,
            ErrorCode.SUCCESS
        );
        return responseData;
    }

    /**
     * Add an extra signer and signature to a Credential. Multiple signatures will be appended in an
     * embedded manner.
     *
     * @param credentialList original credential list
     * @param callerAuth the passed-in privateKey and WeID bundle to sign
     * @return the modified CredentialWrapper
     */
    @Override
    public ResponseData<CredentialPojo> addSignature(
        List<CredentialPojo> credentialList,
        WeIdAuthentication callerAuth) {
        if (credentialList == null || credentialList.size() == 0
            || CredentialPojoUtils.isWeIdAuthenticationValid(callerAuth) != ErrorCode.SUCCESS) {
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        CredentialPojo result = new CredentialPojo();
        result.setCptId(CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);
        result.setIssuanceDate(DateUtils.getNoMillisecondTimeStamp());
        result.setId(UUID.randomUUID().toString());
        result.setContext(CredentialUtils.getDefaultCredentialContext());
        Long expirationDate = 0L;
        for (CredentialPojo arg : credentialList) {
            if (arg.getExpirationDate() > expirationDate) {
                expirationDate = arg.getExpirationDate();
            }
        }
        Long newExpirationDate =
            DateUtils.convertToNoMillisecondTimeStamp(expirationDate);
        if (newExpirationDate == null) {
            logger.error("Create Credential Args illegal.");
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_EXPIRE_DATE_ILLEGAL);
        } else {
            result.setExpirationDate(newExpirationDate);
        }
        // Comment these lines out since we now support multi-public-keys
        // if (!WeIdUtils.validatePrivateKeyWeIdMatches(
        //     callerAuth.getWeIdPrivateKey(),
        //     callerAuth.getWeId())) {
        //     logger.error("Create Credential, private key does not match the current weid.");
        //     return new ResponseData<>(null, ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH);
        // }
        if (!getWeIdService().isWeIdExist(callerAuth.getWeId()).getResult()) {
            return new ResponseData<>(null, ErrorCode.WEID_DOES_NOT_EXIST);
        }
        String privateKey = callerAuth.getWeIdPrivateKey().getPrivateKey();
        CryptoKeyPair keyPair = DataToolUtils.createKeyPairFromPrivate(new BigInteger(privateKey));
        String keyWeId = WeIdUtils.convertAddressToWeId(keyPair.getAddress());

        result.setIssuer(keyWeId);
        result.addType(CredentialConstant.DEFAULT_CREDENTIAL_TYPE);

        List<Map> trimmedCredentialMapList = trimCredentialList(credentialList);

        // The claim will be the wrapper of the to-be-signed credentialpojos
        HashMap<String, Object> claim = new HashMap<>();
        claim.put("credentialList", trimmedCredentialMapList);
        result.setClaim(claim);

        // For embedded signature, salt here is totally meaningless - hence we left it blank
        Map<String, Object> saltMap = DataToolUtils.clone(claim);
        CredentialPojoUtils.clearMap(saltMap);
        String rawData = CredentialPojoUtils
            .getEmbeddedCredentialThumbprintWithoutSig(credentialList);
        String signature = DataToolUtils.secp256k1Sign(rawData, new BigInteger(privateKey));

        result.putProofValue(ParamKeyConstant.PROOF_CREATED, result.getIssuanceDate());

        String weIdPublicKeyId = callerAuth.getWeIdPublicKeyId();
        result.putProofValue(ParamKeyConstant.PROOF_CREATOR, weIdPublicKeyId);

        String proofType = CredentialProofType.ECDSA.getTypeName();
        result.putProofValue(ParamKeyConstant.PROOF_TYPE, proofType);
        result.putProofValue(ParamKeyConstant.PROOF_SIGNATURE, signature);
        result.setSalt(saltMap);

        return new ResponseData<>(result, ErrorCode.SUCCESS);
    }

    private List<Map> trimCredentialList(List<CredentialPojo> credentialList) {
        List<CredentialPojo> trimmedCredentialList = new ArrayList<>();
        for (CredentialPojo arg : credentialList) {
            boolean found = false;
            for (CredentialPojo credAlive : trimmedCredentialList) {
                if (CredentialPojoUtils.isEqual(arg, credAlive)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                ErrorCode errorCode = CredentialPojoUtils.isCredentialPojoValid(arg);
                if (errorCode != ErrorCode.SUCCESS) {
                    return null;
                }
                trimmedCredentialList.add(arg);
            }
        }

        List<Map> trimmedCredentialMapList = new ArrayList<>();
        for (CredentialPojo credAlive : trimmedCredentialList) {
            try {
                trimmedCredentialMapList.add(DataToolUtils.objToMap(credAlive));
            } catch (Exception e) {
                logger.error("Failed to convert Credential to map structure.", e);
                return null;
            }
        }
        return trimmedCredentialMapList;
    }

    /* (non-Javadoc)
     * @see com.webank.weid.rpc.CredentialPojoService#createSelectiveCredential(
     *          com.webank.weid.protocol.base.CredentialPojo,
     *          com.webank.weid.protocol.base.ClaimPolicy
     *      )
     */
    @Override
    public ResponseData<CredentialPojo> createSelectiveCredential(
        CredentialPojo credential,
        ClaimPolicy claimPolicy) {

        if (credential == null) {
            logger.error("[createSelectiveCredential] input credential is null");
            return new ResponseData<CredentialPojo>(null, ErrorCode.ILLEGAL_INPUT);
        }
        if (credential.getType() != null
            && (credential.getType().contains(CredentialType.LITE1.getName())
            || credential.getType().contains(CredentialType.ZKP.getName()))) {
            logger.error(
                "[createSelectiveCredential] Lite Credential and ZKP Credential DO NOT support "
                    + "this function(createSelectiveCredential), type = {}.", credential.getType());
            return new ResponseData<CredentialPojo>(null,
                ErrorCode.CREDENTIAL_NOT_SUPPORT_SELECTIVE_DISCLOSURE);
        }
        try {
            CredentialPojo credentialClone = DataToolUtils.clone(credential);
            ErrorCode checkResp = CredentialPojoUtils.isCredentialPojoValid(credentialClone);
            if (ErrorCode.SUCCESS.getCode() != checkResp.getCode()) {
                return new ResponseData<CredentialPojo>(null, checkResp);
            }
            if (credentialClone.getCptId()
                .equals(CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT)) {
                return new ResponseData<>(null, ErrorCode.CPT_ID_ILLEGAL);
            }
            if (claimPolicy == null) {
                logger.error("[createSelectiveCredential] claimPolicy is null.");
                return new ResponseData<CredentialPojo>(null,
                    ErrorCode.CREDENTIAL_CLAIM_POLICY_NOT_EXIST);
            }
            if (CredentialPojoUtils.isSelectivelyDisclosed(credential.getSalt())) {
                return new ResponseData<CredentialPojo>(null, ErrorCode.CREDENTIAL_RE_DISCLOSED);
            }
            String disclosure = claimPolicy.getFieldsToBeDisclosed();
            Map<String, Object> saltMap = credentialClone.getSalt();
            Map<String, Object> claim = credentialClone.getClaim();

            Map<String, Object> disclosureMap = DataToolUtils
                .deserialize(disclosure, HashMap.class);

            if (!validCredentialMapArgs(claim, saltMap, disclosureMap)) {
                logger.error(
                    "[createSelectiveCredential] create failed. message is {}",
                    ErrorCode.CREDENTIAL_POLICY_FORMAT_DOSE_NOT_MATCH_CLAIM.getCodeDesc()
                );
                return new ResponseData<CredentialPojo>(null,
                    ErrorCode.CREDENTIAL_POLICY_FORMAT_DOSE_NOT_MATCH_CLAIM);
            }
            // 补 policy
            addKeyToPolicy(disclosureMap, claim);
            // 加盐处理
            addSelectSalt(disclosureMap, saltMap, claim, false);
            credentialClone.setSalt(saltMap);

            ResponseData<CredentialPojo> response = new ResponseData<CredentialPojo>();
            response.setResult(credentialClone);
            response.setErrorCode(ErrorCode.SUCCESS);
            return response;
        } catch (DataTypeCastException e) {
            logger.error("Generate SelectiveCredential failed, "
                + "credential disclosure data type illegal. ", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_DISCLOSURE_DATA_TYPE_ILLEGAL);
        } catch (WeIdBaseException e) {
            logger.error("Generate SelectiveCredential failed, "
                + "policy disclosurevalue illegal. ", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_POLICY_DISCLOSUREVALUE_ILLEGAL);
        } catch (Exception e) {
            logger.error("Generate SelectiveCredential failed due to system error. ", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_ERROR);
        }
    }

    /**
     * Get the full hash value of a CredentialPojo. All fields in the CredentialPojo will be
     * included. This method should be called when creating and verifying the Credential Evidence
     * and the result is selectively-disclosure irrelevant.
     *
     * @param credentialPojo the args
     * @return the Credential Hash value
     */
    @Override
    public ResponseData<String> getCredentialPojoHash(CredentialPojo credentialPojo) {
        ErrorCode innerResponse = CredentialPojoUtils.isCredentialPojoValid(credentialPojo);
        if (ErrorCode.SUCCESS.getCode() != innerResponse.getCode()) {
            logger.error("Create Evidence input format error!");
            return new ResponseData<>(StringUtils.EMPTY, innerResponse);
        }
        return new ResponseData<>(CredentialPojoUtils.getCredentialPojoHash(credentialPojo, null),
            ErrorCode.SUCCESS);
    }

    /* (non-Javadoc)
     * @see com.webank.weid.rpc.CredentialPojoService#verify(
     *          java.lang.String,
     *          com.webank.weid.protocol.base.CredentialPojo
     *      )
     */
    @Override
    public ResponseData<Boolean> verify(String issuerWeId, CredentialPojo credential) {

        if (credential == null) {
            logger.error("[verify] The input credential is invalid.");
            return new ResponseData<Boolean>(false, ErrorCode.ILLEGAL_INPUT);
        }

        if (isZkpCredential(credential)) {
            return verifyZkpCredential(credential);
        }

        String issuerId = credential.getIssuer();
        if (!StringUtils.equals(issuerWeId, issuerId)) {
            logger.error("[verify] The input issuer weid is not match the credential's.");
            return new ResponseData<Boolean>(false, ErrorCode.CREDENTIAL_ISSUER_MISMATCH);
        }
        if (CredentialPojoUtils.isLiteCredential(credential)) {
            return verifyLiteCredential(credential, null, null);
        }
        ErrorCode errorCode = verifyContent(credential, null, false, null);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            logger.error("[verify] credential verify failed. error message :{}", errorCode);
            return new ResponseData<Boolean>(false, errorCode);
        }
        return new ResponseData<Boolean>(true, ErrorCode.SUCCESS);
    }

    /* (non-Javadoc)
     * @see com.webank.weid.rpc.CredentialPojoService#verify(
     *          com.webank.weid.protocol.base.CredentialPojo,
     *          com.webank.weid.protocol.base.WeIdPublicKey
     *      )
     */
    @Override
    public ResponseData<Boolean> verify(
        WeIdPublicKey issuerPublicKey,
        CredentialPojo credential) {

        String publicKey = issuerPublicKey.getPublicKey();
        if (StringUtils.isEmpty(publicKey)) {
            return new ResponseData<Boolean>(false, ErrorCode.CREDENTIAL_PUBLIC_KEY_NOT_EXISTS);
        }
        if (CredentialPojoUtils.isLiteCredential(credential)) {
            return verifyLiteCredential(credential, issuerPublicKey.getPublicKey(), null);
        }
        ErrorCode errorCode = verifyContent(credential, publicKey, false, null);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<Boolean>(false, errorCode);
        }
        return new ResponseData<Boolean>(true, ErrorCode.SUCCESS);
    }

    /* (non-Javadoc)
     * @see com.webank.weid.rpc.CredentialPojoService#verify(
     *          java.lang.String,
     *          com.webank.weid.protocol.base.PresentationPolicyE,
     *           com.webank.weid.protocol.base.Challenge,
     *           com.webank.weid.protocol.base.PresentationE
     *       )
     */
    @Override
    public ResponseData<Boolean> verify(
        String presenterWeId,
        PresentationPolicyE presentationPolicyE,
        Challenge challenge,
        PresentationE presentationE) {

        List<String> typeList = presentationE.getType();
        if (typeList.contains(CredentialConstant.PRESENTATION_PDF)) {
            logger.error("[verify] please use verifyPresentationFromPDF function.");
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_USE_VERIFY_FUNCTION_ERROR);
        }

        ErrorCode errorCode =
            checkInputArgs(presenterWeId, presentationPolicyE, challenge, presentationE);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            logger.error("[verify] checkInputArgs fail.");
            return new ResponseData<Boolean>(false, errorCode);
        }

        //verify cptId of presentationE
        List<CredentialPojo> credentialList = presentationE.getVerifiableCredential();
        Map<Integer, ClaimPolicy> policyMap = presentationPolicyE.getPolicy();
        ErrorCode verifyCptIdresult =
            this.verifyCptId(policyMap, credentialList);
        if (verifyCptIdresult.getCode() != ErrorCode.SUCCESS.getCode()) {
            logger.error("[verify] verify cptId failed.");
            return new ResponseData<Boolean>(false, verifyCptIdresult);
        }
        try {
            for (CredentialPojo credential : credentialList) {
                //verify policy
                Integer cptId = credential.getCptId();
                ClaimPolicy claimPolicy = policyMap.get(cptId);
                if (claimPolicy != null) {
                    ErrorCode verifypolicyResult = this
                        .verifyPolicy(credential, claimPolicy, presenterWeId);
                    if (verifypolicyResult.getCode() != ErrorCode.SUCCESS.getCode()) {
                        logger.error("[verify] verify policy {} failed.", policyMap);
                        return new ResponseData<Boolean>(false, verifypolicyResult);
                    }
                }
                //verify credential
                if (isZkpCredential(credential)) {
                    return verifyZkpCredential(credential);

                }
                ErrorCode verifyCredentialResult = verifyContent(credential, null, false, null);
                if (verifyCredentialResult.getCode() != ErrorCode.SUCCESS.getCode()) {
                    logger.error(
                        "[verify] verify credential {} failed.", credential);
                    return new ResponseData<Boolean>(false, verifyCredentialResult);
                }
            }
            return new ResponseData<Boolean>(true, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error(
                "[verify] verify credential error.", e);
            return new ResponseData<Boolean>(false, ErrorCode.UNKNOW_ERROR);
        }
    }

    /* (non-Javadoc)
     * @see com.webank.weid.rpc.CredentialPojoService#verify()
     */
    @Override
    public ResponseData<Boolean> verify(
        String issuerWeId,
        String weIdPublicKeyId,
        CredentialPojo credential
    ) {
        if (credential == null) {
            logger.error("[verify] The input credential is invalid.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (isZkpCredential(credential)) {
            return verifyZkpCredential(credential);
        }
        String issuerId = credential.getIssuer();
        if (!StringUtils.equals(issuerWeId, issuerId)) {
            logger.error("[verify] The input issuer weid is not match the credential's.");
            return new ResponseData<Boolean>(false, ErrorCode.CREDENTIAL_ISSUER_MISMATCH);
        }
        if (CredentialPojoUtils.isLiteCredential(credential)) {
            return verifyLiteCredential(credential, null, weIdPublicKeyId);
        }
        ErrorCode errorCode = verifyContent(credential, null, false, weIdPublicKeyId);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            logger.error("[verify] credential verify failed. error message :{}", errorCode);
            return new ResponseData<Boolean>(false, errorCode);
        }
        return new ResponseData<Boolean>(true, ErrorCode.SUCCESS);
    }

    /* (non-Javadoc)
     * @see com.webank.weid.rpc.CredentialPojoService#verify(
     *          com.webank.weid.protocol.base.CredentialPojo,
     *          com.webank.weid.protocol.base.WeIdPublicKey
     *      )
     */
    @Override
    public ResponseData<Boolean> verifyOffline(
        WeIdPublicKey issuerPublicKey,
        CredentialPojo credential) {

        String publicKey = issuerPublicKey.getPublicKey();
        if (StringUtils.isEmpty(publicKey)) {
            return new ResponseData<Boolean>(false, ErrorCode.CREDENTIAL_PUBLIC_KEY_NOT_EXISTS);
        }
        if (CredentialPojoUtils.isLiteCredential(credential)) {
            return verifyLiteCredential(credential, issuerPublicKey.getPublicKey(), null);
        }
        ErrorCode errorCode = verifyContent(credential, publicKey, true, null);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<Boolean>(false, errorCode);
        }
        return new ResponseData<Boolean>(true, ErrorCode.SUCCESS);
    }

    @Override
    public ResponseData<Boolean> verifyPresentationFromPdf(
        String pdfTemplatePath,
        byte[] serializePdf,
        String presenterWeId,
        PresentationPolicyE presentationPolicyE,
        Challenge challenge,
        PresentationE presentationE) {

        //verify pdf
        PdfAttributeInfo pdfAttributeInfo = getPdfTransportation().getBaseData(serializePdf);
        if (pdfAttributeInfo == null) {
            logger.error("[verifyPresentationFromPDF] get pdf base data error.");
        }
        Boolean retVerifyPdf = getPdfTransportation().verifyPdf(
            presentationE,
            pdfTemplatePath,
            pdfAttributeInfo,
            serializePdf
        );

        if (!retVerifyPdf) {
            logger.error("[verifyPresentationFromPDF] verify pdf error.");
            return new ResponseData<>(false, ErrorCode.TRANSPORTATION_PDF_VERIFY_ERROR);
        }

        List<String> typeList = presentationE.getType();
        if (typeList.contains(CredentialConstant.PRESENTATION_PDF)) {
            typeList.remove(CredentialConstant.PRESENTATION_PDF);
        }
        presentationE.setType(typeList);

        return this.verify(presenterWeId, presentationPolicyE, challenge, presentationE);
    }

    private ErrorCode checkInputArgs(
        String presenterWeId,
        PresentationPolicyE presentationPolicyE,
        Challenge challenge,
        PresentationE presentationE) {

        if (StringUtils.isBlank(presenterWeId)
            || challenge == null
            || StringUtils.isBlank(challenge.getNonce())
            || !CredentialPojoUtils.checkPresentationPolicyEValid(presentationPolicyE)) {
            logger.error("[verify] presentation verify failed, please check your input.");
            return ErrorCode.ILLEGAL_INPUT;
        }

        ErrorCode errorCode = CredentialPojoUtils.checkPresentationEValid(presentationE);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            logger.error(
                "[verify] presentation verify failed, error message : {}",
                errorCode.getCodeDesc()
            );
            return errorCode;
        }

        //verify presenterWeId
        if (StringUtils.isNotBlank(challenge.getWeId())
            && !presenterWeId.equals(challenge.getWeId())) {
            logger.error("[verify] The input issuer weid is not match the presentian's.");
            return ErrorCode.CREDENTIAL_PRESENTERWEID_NOTMATCH;
        }

        //verify challenge
        if (!challenge.getNonce().equals(presentationE.getNonce())) {
            logger
                .error("[verify] The nonce of challenge is not matched with the presentationE's.");
            return ErrorCode.PRESENTATION_CHALLENGE_NONCE_MISMATCH;
        }

        //verify Signature of PresentationE
        WeIdDocument weIdDocument = getWeIdService().getWeIdDocument(presenterWeId).getResult();
        if (weIdDocument == null) {
            logger.error(
                "[verify]presentation verify failed, because the presenter weid :{} "
                    + "does not exist.",
                presenterWeId);
            return ErrorCode.WEID_DOES_NOT_EXIST;
        }
        String signature = presentationE.getSignature();
        errorCode =
            DataToolUtils
                .verifySecp256k1SignatureFromWeId(presentationE.toRawData(), signature,
                    weIdDocument, null);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return ErrorCode.PRESENTATION_SIGNATURE_MISMATCH;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode verifyCptId(
        Map<Integer, ClaimPolicy> policyMap,
        List<CredentialPojo> credentialList) {

        if (policyMap.size() > credentialList.size()) {
            return ErrorCode.CREDENTIAL_CPTID_NOTMATCH;
        } else {
            for (CredentialPojo credential : credentialList) {
                if (isZkpCredential(credential)) {
                    continue;
                } else {
                    Integer cptId = credential.getCptId();
                    if (cptId == null || !policyMap.containsKey(cptId)) {
                        return ErrorCode.CREDENTIAL_CPTID_NOTMATCH;
                    }
                }
            }
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode verifyDisclosureAndSalt(
        Map<String, Object> disclosureMap,
        Map<String, Object> saltMap) {

        for (String disclosureK : disclosureMap.keySet()) {
            Object disclosureV = disclosureMap.get(disclosureK);
            Object saltV = saltMap.get(disclosureK);
            if (disclosureV instanceof Map) {
                ErrorCode code = verifyDisclosureAndSalt((HashMap) disclosureV, (HashMap) saltV);
                if (code.getCode() != ErrorCode.SUCCESS.getCode()) {
                    return code;
                }
            } else if (disclosureV instanceof List) {
                ArrayList<Object> disclosurs = (ArrayList<Object>) disclosureV;
                ErrorCode code = verifyDisclosureAndSaltList(disclosurs, (ArrayList<Object>) saltV);
                if (code.getCode() != ErrorCode.SUCCESS.getCode()) {
                    return code;
                }
            } else {
                String disclosure = String.valueOf(disclosureV);

                if (saltV == null
                    || (!disclosure.equals(NOT_DISCLOSED) && !disclosure.equals(DISCLOSED)
                    && !disclosure.equals(EXISTED))) {
                    logger.error(
                        "[verifyDisclosureAndSalt] policy disclosureValue {} illegal.",
                        disclosureMap
                    );
                    return ErrorCode.CREDENTIAL_POLICY_DISCLOSUREVALUE_ILLEGAL;
                }

                String salt = String.valueOf(saltV);
                if ((disclosure.equals(NOT_DISCLOSED) && salt.length() > 1)
                    || (disclosure.equals(NOT_DISCLOSED) && !salt.equals(NOT_DISCLOSED))) {
                    return ErrorCode.CREDENTIAL_DISCLOSUREVALUE_NOTMATCH_SALTVALUE;
                }

                if (disclosure.equals(DISCLOSED) && salt.length() <= 1) {
                    return ErrorCode.CREDENTIAL_DISCLOSUREVALUE_NOTMATCH_SALTVALUE;
                }
            }
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode verifyDisclosureAndSaltList(
        List<Object> disclosureList,
        List<Object> saltList
    ) {
        for (int i = 0; i < disclosureList.size(); i++) {
            Object disclosure = disclosureList.get(i);
            Object saltV = saltList.get(i);
            if (disclosure instanceof Map) {
                ErrorCode code =
                    verifyDisclosureAndSaltList(
                        (HashMap) disclosure,
                        (ArrayList<Object>) saltList
                    );
                if (code.getCode() != ErrorCode.SUCCESS.getCode()) {
                    return code;
                }
            } else if (disclosure instanceof List) {
                ErrorCode code =
                    verifyDisclosureAndSaltList(
                        (ArrayList<Object>) disclosure,
                        (ArrayList<Object>) saltV
                    );
                if (code.getCode() != ErrorCode.SUCCESS.getCode()) {
                    return code;
                }
            }
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode verifyDisclosureAndSaltList(
        Map<String, Object> disclosure,
        List<Object> saltList
    ) {
        for (int i = 0; i < saltList.size(); i++) {
            Object saltV = saltList.get(i);
            ErrorCode code = verifyDisclosureAndSalt((HashMap) disclosure, (HashMap) saltV);
            if (code.getCode() != ErrorCode.SUCCESS.getCode()) {
                return code;
            }
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode verifyPolicy(CredentialPojo credentialPojo, ClaimPolicy claimPolicy,
        String presenterWeId) {
        if (isZkpCredential(credentialPojo)) {
            return ErrorCode.SUCCESS;
        }
        Map<String, Object> saltMap = credentialPojo.getSalt();
        String disclosure = claimPolicy.getFieldsToBeDisclosed();
        Map<String, Object> disclosureMap = DataToolUtils.deserialize(disclosure, HashMap.class);

        Object idValue = disclosureMap.get("id");
        if (idValue != null) {
            Object weid = credentialPojo.getClaim().get("id");
            if (StringUtils.equals(String.valueOf(idValue), DISCLOSED)) {
                if (!StringUtils.equals(String.valueOf(weid), presenterWeId)) {
                    logger.error(
                        "[verifyPolicy] the presenter weid->{} of presentation does not "
                            + "match the credential's ->{}. ",
                        presenterWeId,
                        weid);
                    return ErrorCode.PRESENTATION_WEID_CREDENTIAL_WEID_MISMATCH;
                }
            } else if (StringUtils.equals(String.valueOf(idValue), EXISTED)
                && !credentialPojo.getClaim().containsKey("id")) {
                logger.error(
                    "[verifyPolicy] the presenter weid->{} of presentation does not "
                        + "match the credential's ->{}. ",
                    presenterWeId,
                    weid);
                return ErrorCode.PRESENTATION_CREDENTIAL_CLAIM_WEID_NOT_EXIST;
            }
        }
        return this.verifyDisclosureAndSalt(disclosureMap, saltMap);
    }

    @Override
    public ResponseData<PresentationE> createPresentation(
        List<CredentialPojo> credentialList,
        PresentationPolicyE presentationPolicyE,
        Challenge challenge,
        WeIdAuthentication weIdAuthentication) {

        PresentationE presentation = new PresentationE();
        try {
            // 检查输入数据完整性
            ErrorCode errorCode =
                validateCreateArgs(
                    credentialList,
                    presentationPolicyE,
                    challenge,
                    weIdAuthentication
                );
            if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
                logger.error(
                    "check input error:{}-{}",
                    errorCode.getCode(),
                    errorCode.getCodeDesc()
                );
                return new ResponseData<PresentationE>(null, errorCode);
            }
            // 处理credentialList数据
            errorCode = processCredentialList(credentialList, presentationPolicyE, presentation,
                weIdAuthentication.getWeId());
            if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
                logger.error(
                    "process credentialList error:{}-{}",
                    errorCode.getCode(),
                    errorCode.getCodeDesc()
                );
                return new ResponseData<PresentationE>(null, errorCode);
            }
            presentation.getContext().add(CredentialConstant.DEFAULT_CREDENTIAL_CONTEXT);
            presentation.getType().add(WeIdConstant.DEFAULT_PRESENTATION_TYPE);
            // 处理proof数据
            generatePresentationProof(challenge, weIdAuthentication, presentation);
            return new ResponseData<PresentationE>(presentation, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("create PresentationE error", e);
            return new ResponseData<PresentationE>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    private ErrorCode validateCreateArgs(
        List<CredentialPojo> credentialList,
        PresentationPolicyE presentationPolicyE,
        Challenge challenge,
        WeIdAuthentication weIdAuthentication) {

        if (challenge == null || weIdAuthentication == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (StringUtils.isBlank(challenge.getNonce())
            || challenge.getVersion() == null) {
            return ErrorCode.PRESENTATION_CHALLENGE_INVALID;
        }
        if (weIdAuthentication.getWeIdPrivateKey() == null
            || !WeIdUtils.validatePrivateKeyWeIdMatches(
            weIdAuthentication.getWeIdPrivateKey(), weIdAuthentication.getWeId())) {
            return ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH;
        }
        if (!StringUtils.isBlank(challenge.getWeId())
            && !challenge.getWeId().equals(weIdAuthentication.getWeId())) {
            return ErrorCode.PRESENTATION_CHALLENGE_WEID_MISMATCH;
        }
        if (StringUtils.isBlank(weIdAuthentication.getWeIdPublicKeyId())) {
            return ErrorCode.PRESENTATION_WEID_PUBLICKEY_ID_INVALID;
        }
        return validateClaimPolicy(credentialList, presentationPolicyE);
    }

    private ErrorCode validateClaimPolicy(
        List<CredentialPojo> credentialList,
        PresentationPolicyE presentationPolicyE) {
        if (CollectionUtils.isEmpty(credentialList)) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (presentationPolicyE == null || presentationPolicyE.getPolicy() == null) {
            return ErrorCode.PRESENTATION_POLICY_INVALID;
        }
        if (!WeIdUtils.isWeIdValid(presentationPolicyE.getPolicyPublisherWeId())) {
            return ErrorCode.PRESENTATION_POLICY_PUBLISHER_WEID_INVALID;
        }
        ResponseData<Boolean> weIdRes = getWeIdService()
            .isWeIdExist(presentationPolicyE.getPolicyPublisherWeId());
        if (ErrorCode.SUCCESS.getCode() != weIdRes.getErrorCode() || !weIdRes.getResult()) {
            return ErrorCode.PRESENTATION_POLICY_PUBLISHER_WEID_NOT_EXIST;
        }
        for (CredentialPojo credentialPojo : credentialList) {
            ErrorCode checkResp = CredentialPojoUtils.isCredentialPojoValid(credentialPojo);
            if (ErrorCode.SUCCESS.getCode() != checkResp.getCode()) {
                return checkResp;
            }
        }
        List<Integer> cptIdList = credentialList.stream().map(
            cpwl -> cpwl.getCptId()).collect(Collectors.toList());
        Set<Integer> claimPolicyCptSet = presentationPolicyE.getPolicy().keySet();
        if (!cptIdList.containsAll(claimPolicyCptSet)) {
            return ErrorCode.PRESENTATION_CREDENTIALLIST_MISMATCH_CLAIM_POLICY;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode processCredentialList(
        List<CredentialPojo> credentialList,
        PresentationPolicyE presentationPolicy,
        PresentationE presentation,
        String userId) {

        List<CredentialPojo> newCredentialList = new ArrayList<>();
        // 获取ClaimPolicyMap
        Map<Integer, ClaimPolicy> claimPolicyMap = presentationPolicy.getPolicy();

        String policyType = presentationPolicy.getPolicyType();
        if (StringUtils.equals(policyType, CredentialType.ZKP.getName())) {
            newCredentialList = generateZkpCredentialList(credentialList, presentationPolicy,
                userId);
        } else {
            // 遍历所有原始证书
            for (CredentialPojo credential : credentialList) {
                // 根据原始证书获取对应的 claimPolicy
                ClaimPolicy claimPolicy = claimPolicyMap.get(credential.getCptId());
                if (claimPolicy == null) {
                    continue;
                }
                // 根据原始证书和claimPolicy去创建选择性披露凭证
                ResponseData<CredentialPojo> res =
                    this.createSelectiveCredential(credential, claimPolicy);
                if (res.getErrorCode().intValue() != ErrorCode.SUCCESS.getCode()) {
                    return ErrorCode.getTypeByErrorCode(res.getErrorCode().intValue());
                }
                newCredentialList.add(res.getResult());
            }
        }

        presentation.setVerifiableCredential(newCredentialList);
        return ErrorCode.SUCCESS;
    }

    private List<CredentialPojo> generateZkpCredentialList(
        List<CredentialPojo> credentialList,
        PresentationPolicyE presentationPolicy,
        String userId) {

        List<CredentialPojo> newCredentialList = new ArrayList<>();
        // 获取ClaimPolicyMap
        Map<Integer, ClaimPolicy> claimPolicyMap = presentationPolicy.getPolicy();
        for (CredentialPojo credential : credentialList) {
            // 根据原始证书获取对应的 claimPolicy
            ClaimPolicy claimPolicy = claimPolicyMap.get(credential.getCptId());
            if (claimPolicy == null) {
                continue;
            }
            // 根据原始证书和claimPolicy去创建选择性披露凭证
            ResponseData<CredentialPojo> res = this
                .createZkpCredential(credential, claimPolicy, userId);

            if (res.getErrorCode().intValue() != ErrorCode.SUCCESS.getCode()) {
                return null;
            }
            newCredentialList.add(res.getResult());
        }

        return newCredentialList;
    }

    private void generatePresentationProof(
        Challenge challenge,
        WeIdAuthentication weIdAuthentication,
        PresentationE presentation) {

        String proofType = CredentialProofType.ECDSA.getTypeName();
        presentation.putProofValue(ParamKeyConstant.PROOF_TYPE, proofType);

        Long proofCreated = DateUtils.getNoMillisecondTimeStamp();
        presentation.putProofValue(ParamKeyConstant.PROOF_CREATED, proofCreated);

        String weIdPublicKeyId = weIdAuthentication.getWeIdPublicKeyId();
        presentation.putProofValue(ParamKeyConstant.PROOF_VERIFICATION_METHOD, weIdPublicKeyId);
        presentation.putProofValue(ParamKeyConstant.PROOF_NONCE, challenge.getNonce());
        String signature =
            DataToolUtils.secp256k1Sign(
                presentation.toRawData(),
                new BigInteger(weIdAuthentication.getWeIdPrivateKey().getPrivateKey())
            );
        presentation.putProofValue(ParamKeyConstant.PROOF_SIGNATURE, signature);
    }

    /**
     * Create a trusted timestamp credential.
     *
     * @param credentialList the credentialPojo list to be signed
     * @param weIdAuthentication the caller authentication
     * @return the embedded timestamp in credentialPojo
     */
    @Override
    public ResponseData<CredentialPojo> createTrustedTimestamp(
        List<CredentialPojo> credentialList,
        WeIdAuthentication weIdAuthentication) {
        if (credentialList == null || credentialList.size() == 0
            || CredentialPojoUtils.isWeIdAuthenticationValid(weIdAuthentication)
            != ErrorCode.SUCCESS) {
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }

        // For business reasons, we do not allow a selectively disclosed credential to be stamped.
        if (CredentialPojoUtils.isSelectivelyDisclosedCredentialList(credentialList)) {
            return new ResponseData<>(null,
                ErrorCode.TIMESTAMP_CREATION_FAILED_FOR_SELECTIVELY_DISCLOSED);
        }

        CredentialPojo credential = new CredentialPojo();
        credential.setCptId(CredentialConstant.EMBEDDED_TIMESTAMP_CPT);
        String privateKey = weIdAuthentication.getWeIdPrivateKey().getPrivateKey();
        CryptoKeyPair keyPair = DataToolUtils.createKeyPairFromPrivate(new BigInteger(privateKey));
        String keyWeId = WeIdUtils.convertAddressToWeId(keyPair.getAddress());
        credential.setIssuer(keyWeId);
        credential.setIssuanceDate(DateUtils.getNoMillisecondTimeStamp());
        credential.setId(UUID.randomUUID().toString());
        credential.setContext(CredentialUtils.getDefaultCredentialContext());
        // WeSign default valid: 1 year
        credential.setExpirationDate(DateUtils.getNoMillisecondTimeStamp() + 31536000L);
        credential.addType(CredentialConstant.DEFAULT_CREDENTIAL_TYPE);

        String rawData = CredentialPojoUtils
            .getEmbeddedCredentialThumbprintWithoutSig(credentialList);
        if (StringUtils.isEmpty(rawData)) {
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        ResponseData<HashMap<String, Object>> claimResp = TimestampUtils
            .createWeSignTimestamp(rawData);
        if (claimResp.getResult() == null) {
            return new ResponseData<>(null, claimResp.getErrorCode(), claimResp.getErrorMessage());
        }
        HashMap<String, Object> claim = claimResp.getResult();
        List<Map> trimmedCredentialMapList = trimCredentialList(credentialList);
        claim.put("credentialList", trimmedCredentialMapList);
        credential.setClaim(claim);

        // For embedded signature, salt here is totally meaningless - hence we left it blank
        Map<String, Object> saltMap = DataToolUtils.clone(claim);
        CredentialPojoUtils.clearMap(saltMap);
        String signature = DataToolUtils.secp256k1Sign(rawData, new BigInteger(privateKey));

        credential.putProofValue(ParamKeyConstant.PROOF_CREATED, credential.getIssuanceDate());

        String weIdPublicKeyId = weIdAuthentication.getWeIdPublicKeyId();
        credential.putProofValue(ParamKeyConstant.PROOF_CREATOR, weIdPublicKeyId);

        String proofType = CredentialProofType.ECDSA.getTypeName();
        credential.putProofValue(ParamKeyConstant.PROOF_TYPE, proofType);
        credential.putProofValue(ParamKeyConstant.PROOF_SIGNATURE, signature);
        credential.setSalt(saltMap);

        return new ResponseData<>(credential, ErrorCode.SUCCESS);
    }

    /* (non-Javadoc)
     * @see com.webank.weid.rpc.CredentialPojoService#prepareZKPCredential(
     * com.webank.weid.protocol.base.CredentialPojo, java.lang.Object)
     */
    @Override
    public ResponseData<CredentialPojo> prepareZkpCredential(
        CredentialPojo preCredential,
        String claimJson,
        WeIdAuthentication weIdAuthentication) {

        //1. verify pre-credential.
        ResponseData<Boolean> verifyResult = this.verify(preCredential.getIssuer(), preCredential);
        if (verifyResult.getErrorCode().intValue() != ErrorCode.SUCCESS.getCode()) {
            logger.error("[prepareZKPCredential] pre-credential verified failed.");
            return new ResponseData<CredentialPojo>(null,
                ErrorCode.getTypeByErrorCode(verifyResult.getErrorCode()));
        }

        //2.build credentialInfoMap and make credential.
        Integer cptId = (Integer) preCredential.getClaim()
            .get(CredentialConstant.CREDENTIAL_META_KEY_CPTID);
        UserResult userResult = makeCredential(preCredential, claimJson, cptId, weIdAuthentication);

        //3. generate credential based on CPT 111 and userResult.
        return generateCpt111Credential(weIdAuthentication, cptId, userResult);
    }

    /**
     * generate credential based on cpt 111.
     *
     * @param weIdAuthentication auth
     * @param cptId cpt id
     * @param userResult userResult made by user
     * @return credential signed by user.
     */
    private ResponseData<CredentialPojo> generateCpt111Credential(
        WeIdAuthentication weIdAuthentication,
        Integer cptId,
        UserResult userResult) {

        Cpt111 cpt111 = new Cpt111();
        cpt111.setCptId(String.valueOf(cptId));
        cpt111.setCredentialSignatureRequest(userResult.credentialSignatureRequest);
        cpt111.setUserNonce(userResult.userNonce);
        CreateCredentialPojoArgs args = new CreateCredentialPojoArgs();
        args.setClaim(cpt111);
        args.setWeIdAuthentication(weIdAuthentication);
        args.setCptId(CredentialConstant.ZKP_USER_NONCE_CPT);
        args.setIssuer(weIdAuthentication.getWeId());
        //args.setId(preCredential.getId());
        args.setIssuanceDate(System.currentTimeMillis());
        args.setExpirationDate(System.currentTimeMillis() + 24 * 60 * 60 * 1000);
        return this.createCredential(args);
    }

    private ResponseData<CredentialPojo> createZkpCredential(
        CredentialPojo credential,
        ClaimPolicy claimPolicy,
        String userId) {
        try {
            CredentialPojo credentialClone = DataToolUtils.clone(credential);
            ErrorCode checkResp = CredentialPojoUtils.isCredentialPojoValid(credentialClone);
            if (ErrorCode.SUCCESS.getCode() != checkResp.getCode()) {
                return new ResponseData<CredentialPojo>(null, checkResp);
            }
            if (credentialClone.getCptId()
                .equals(CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT)) {
                return new ResponseData<>(null, ErrorCode.CPT_ID_ILLEGAL);
            }
            if (claimPolicy == null) {
                logger.error("[createZkpCredential] claimPolicy is null.");
                return new ResponseData<CredentialPojo>(null,
                    ErrorCode.CREDENTIAL_CLAIM_POLICY_NOT_EXIST);
            }
            List<String> revealedAttributeList = new ArrayList<>();
            List<Predicate> predicateList = new ArrayList<>();

            processZkpPolicy(claimPolicy, revealedAttributeList, predicateList);
            VerificationRule verificationRule =
                VerificationRule.newBuilder()
                    .addAllRevealedAttribute(revealedAttributeList)
                    .addAllPredicateAttribute(predicateList)
                    .build();
            String encodedVerificationRule = Utils.protoToEncodedString(verificationRule);
            ResponseData<String> dbResp =
                getDataDriver().get(
                    DataDriverConstant.DOMAIN_USER_CREDENTIAL_SIGNATURE,
                    credential.getId());
            Integer cptId = credentialClone.getCptId();
            String id = new StringBuffer().append(userId).append("_").append(cptId).toString();
            String newCredentialSignature = dbResp.getResult();
            ResponseData<String> masterKeyResp =
                getDataDriver().get(
                    DataDriverConstant.DOMAIN_USER_MASTER_SECRET,
                    id);
            HashMap<String, String> userCredentialInfo = DataToolUtils
                .deserialize(masterKeyResp.getResult(), HashMap.class);
            String masterSecret = userCredentialInfo.get("masterSecret");
            ResponseData<CredentialTemplateEntity> credentialTemplateResp = getCptService()
                .queryCredentialTemplate(cptId);
            CredentialTemplateEntity credentialTemplate = credentialTemplateResp.getResult();
            Map<String, String> credentialInfoMap = new HashMap<>();
            credentialInfoMap = JsonUtil.credentialToMonolayer(credential);
            UserResult userResult =
                UserClient.proveCredentialInfo(
                    encodedVerificationRule,
                    newCredentialSignature, //from db
                    credentialInfoMap,  //from credential
                    credentialTemplate, //from blockchain and cpt
                    masterSecret); //from db

            String verificationRequest = userResult.verificationRequest;

            porcessZkpDisclosedValue(credentialClone, claimPolicy);
            //CredentialPojo zkpCredential = new CredentialPojo();
            credentialClone.setProof(null);
            credentialClone
                .putProofValue(ParamKeyConstant.PROOF_VERIFICATIONREQUEST, verificationRequest);
            credentialClone.putProofValue(ParamKeyConstant.PROOF_ENCODEDVERIFICATIONRULE,
                encodedVerificationRule);
            List<String> zkpTyps = new ArrayList<>();
            zkpTyps.add(CredentialConstant.DEFAULT_CREDENTIAL_TYPE);
            zkpTyps.add(CredentialType.ZKP.getName());
            credentialClone.setType(zkpTyps);
            return new ResponseData<CredentialPojo>(credentialClone, ErrorCode.SUCCESS);
        } catch (DataTypeCastException e) {
            logger.error("Generate SelectiveCredential failed, "
                + "credential disclosure data type illegal. ", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_DISCLOSURE_DATA_TYPE_ILLEGAL);
        } catch (WeIdBaseException e) {
            logger.error("Generate SelectiveCredential failed, "
                + "policy disclosurevalue illegal. ", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_POLICY_DISCLOSUREVALUE_ILLEGAL);
        } catch (Exception e) {
            logger.error("Generate SelectiveCredential failed due to system error. ", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_ERROR);
        }

    }

    private void porcessZkpDisclosedValue(CredentialPojo credential, ClaimPolicy claimPolicy) {

        String disclosure = claimPolicy.getFieldsToBeDisclosed();
        Map<String, Object> saltMap = credential.getSalt();
        Map<String, Object> claim = credential.getClaim();

        Map<String, Object> disclosureMap = DataToolUtils
            .deserialize(disclosure, HashMap.class);

        Map<String, Object> claimDisclosureMap = (Map<String, Object>) disclosureMap.get("claim");
        if (claimDisclosureMap == null || !(claimDisclosureMap instanceof Map)) {
            return;
        }
        // 补 policy
        addKeyToPolicy(claimDisclosureMap, claim);
        // 加盐处理
        addSelectSalt(claimDisclosureMap, saltMap, claim, true);

        disclosureMap.remove("claim");
        processMetaDisclosedValue(credential, disclosureMap);

    }

    private void processMetaDisclosedValue(CredentialPojo credential,
        Map<String, Object> disclosureMap) {

        for (Map.Entry<String, Object> entry : disclosureMap.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            String salt = DataToolUtils.getRandomSalt();
            if ((value instanceof Map) || !StringUtils.equals(String.valueOf(value), DISCLOSED)) {
                switch (key) {
                    case CredentialConstant.ID:
                        credential
                            .setId(CredentialPojoUtils.getFieldSaltHash(credential.getId(), salt));
                        break;
                    case CredentialConstant.CREDENTIAL_META_KEY_ISSUANCEDATE:
                        credential.setIssuanceDate(0L);
                        break;
                    case CredentialConstant.CREDENTIAL_META_KEY_EXPIRATIONDATE:
                        credential.setExpirationDate(0L);
                        break;
                    case CredentialConstant.CREDENTIAL_META_KEY_CPTID:
                        credential.setCptId(0);
                        break;
                    case CredentialConstant.CREDENTIAL_META_KEY_ISSUER:
                        credential.setIssuer(
                            CredentialPojoUtils.getFieldSaltHash(credential.getIssuer(), salt));
                        break;
                    case CredentialConstant.CREDENTIAL_META_KEY_CONTEXT:
                        credential.setIssuer(
                            CredentialPojoUtils.getFieldSaltHash(credential.getContext(), salt));
                        break;
                    default:
                        break;
                }
            }
        }
    }

    /* (non-Javadoc)
     * @see com.webank.weid.rpc.CredentialPojoService#createDataAuthToken()
     */
    @Override
    public ResponseData<CredentialPojo> createDataAuthToken(
        Cpt101 authInfo,
        WeIdAuthentication weIdAuthentication) {
        ErrorCode innerErrorCode =
            CredentialPojoUtils.isWeIdAuthenticationValid(weIdAuthentication);
        if (innerErrorCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(null, innerErrorCode);
        }

        CreateCredentialPojoArgs args = new CreateCredentialPojoArgs();
        args.setClaim(authInfo);
        args.setWeIdAuthentication(weIdAuthentication);
        args.setId(UUID.randomUUID().toString());
        args.setContext(CredentialUtils.getDefaultCredentialContext());
        args.setCptId(CredentialConstant.AUTHORIZATION_CPT);
        String privateKey = weIdAuthentication.getWeIdPrivateKey().getPrivateKey();
        CryptoKeyPair keyPair = DataToolUtils.createKeyPairFromPrivate(new BigInteger(privateKey));
        String keyWeId = WeIdUtils.convertAddressToWeId(keyPair.getAddress());
        args.setIssuer(keyWeId);
        args.setIssuanceDate(DateUtils.getNoMillisecondTimeStamp());
        args.setExpirationDate(args.getIssuanceDate() + authInfo.getDuration());
        ResponseData<CredentialPojo> resp = this.createCredential(args);
        innerErrorCode = verifyAuthClaim(resp.getResult());
        if (innerErrorCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(null, innerErrorCode);
        }
        return resp;
    }

    @Override
    public ResponseData<ProcessingReport> checkCredentialWithCpt(
        CredentialPojo credential, 
        Cpt cpt
    ) {
        try {
            if (credential == null || credential.getSalt() == null 
                || credential.getClaim() == null || credential.getType() == null) {
                String errorMsg = ErrorCode.ILLEGAL_INPUT.getCodeDesc() + ": credential";
                logger.error("[checkCredentialWithCpt] {}.", errorMsg);
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT.getCode(), errorMsg);
            }
            if (cpt == null || cpt.getCptJsonSchema() == null) {
                String errorMsg = ErrorCode.ILLEGAL_INPUT.getCodeDesc() + ": cpt";
                logger.error("[checkCredentialWithCpt] {}.", errorMsg);
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT.getCode(), errorMsg);
            }
            if (credential.getCptId().intValue() != cpt.getCptId().intValue()) {
                logger.error("[checkCredentialWithCpt] the cptId does not match.");
                return new ResponseData<>(null, ErrorCode.CREDENTIAL_CPTID_NOTMATCH);
            }
            // zkp不支持检查
            if (credential.getCredentialType() == CredentialType.ZKP) {
                logger.error("[checkCredentialWithCpt] ZKP Credential DO NOT support.");
                return new ResponseData<>(null, ErrorCode.THIS_IS_UNSUPPORTED);
            } else if (credential.getCredentialType() == CredentialType.ORIGINAL) {
                // 如果不是lite1类型的，则判断是否为选择性披露类型
                boolean isSelectivelyDisclosed = CredentialPojoUtils.isSelectivelyDisclosed(
                    credential.getSalt());
                // 如果是选择性披露 则特殊处理
                if (isSelectivelyDisclosed) {
                    // 做特殊处理逻辑: remove不披露的字段 并判断是否为必选字段，如果是必选字段 并且为不披露则检查失败
                    credential = DataToolUtils.clone(credential);
                    removeDisclosedFiledMap(
                        credential.getClaim(), 
                        credential.getSalt(), 
                        cpt.getCptJsonSchema()
                    );
                }
            }
           
            String cptJsonSchema = DataToolUtils.serialize(cpt.getCptJsonSchema());
            // 验证cp自身的合法性
            if (!DataToolUtils.isCptJsonSchemaValid(cptJsonSchema)) {
                logger.error("[checkCredentialWithCpt] the cpt invalid.");
                return new ResponseData<>(null, ErrorCode.CPT_JSON_SCHEMA_INVALID);
            }
            String claimStr = DataToolUtils.serialize(credential.getClaim());
            // 验证cpt与credential的匹配性
            ProcessingReport checkRes = DataToolUtils.checkJsonVersusSchema(
                claimStr, cptJsonSchema);
            if (!checkRes.isSuccess()) {
                logger.error(
                    "[checkCredentialWithCpt] check fail, ProcessingReport = {}.", checkRes);
                ResponseData<ProcessingReport> result = new ResponseData<>(
                    checkRes, 
                    ErrorCode.CREDENTIAL_DOES_NOT_MATCHE_THE_CPT
                );
                return result;
            }
            return new ResponseData<>(checkRes, ErrorCode.SUCCESS);
        } catch (WeIdBaseException e) {
            logger.error("[checkCredentialWithCpt] check has base exception.", e);
            return new ResponseData<>(null, e.getErrorCode().getCode(), e.getMessage());
        } catch (Exception e) {
            logger.error("[checkCredentialWithCpt] check has unknown exception.", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }
    
    // 移除不披露的字段
    private void removeDisclosedFiledMap(
        Map<String, Object> claim, 
        Map<String, Object> salt, 
        Map<String, Object> properties
    ) {
        ArrayList<String> requireds = (ArrayList<String>)properties.get("required");
        Map<String, Object> nextProperties = (Map<String, Object>)properties.get("properties"); 
        // 遍历claim
        for (Map.Entry<String, Object> entry : salt.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof Map) {
                // 说明下一层为map
                removeDisclosedFiledMap(
                    (Map<String, Object>) claim.get(key), 
                    (Map<String, Object>) value, 
                    (Map<String, Object>) nextProperties.get(key)
                );
            } else if (value instanceof List) {
                // 说明下一层是List
                removeDisclosedFiledList(
                    (ArrayList<Object>) claim.get(key), 
                    (ArrayList<Object>) value, 
                    (Map<String, Object>) nextProperties.get(key));
            } else {
                // 说明当前层为需要处理的层
                // 如果当前为不披露的key
                // 1. 如果必须的key则报错
                // 2. 否则移除此key
                if ("0".equals(value.toString())) {
                    // 说明是选择性披露
                    if (requireds != null && requireds.contains(key)) {
                        throw new WeIdBaseException(key + " is required and disclosed.");
                    } else {
                        claim.remove(key);
                    }
                }
            }
        }
    }
    
    private void removeDisclosedFiledList(
        ArrayList<Object> claims, 
        ArrayList<Object> salts, 
        Map<String, Object> properties
    ) {
        for (int i = 0; i < claims.size(); i++) {
            Object claim = claims.get(i);
            if (claim instanceof Map) {
                removeDisclosedFiledMap(
                    (Map<String, Object>) claim, 
                    (Map<String, Object>) salts.get(i), 
                    (Map<String, Object>) properties.get("items")
                ); 
            } else {
                removeDisclosedFiledList(
                    (ArrayList<Object>) claim, 
                    (ArrayList<Object>) salts.get(i), 
                    (Map<String, Object>) properties.get("items")
                );
            }
        }
    } 
}
