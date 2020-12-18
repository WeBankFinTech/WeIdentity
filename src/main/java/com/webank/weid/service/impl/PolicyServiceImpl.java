package com.webank.weid.service.impl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.collections4.CollectionUtils;
import org.fisco.bcos.sdk.crypto.signature.ECDSASignatureResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.protocol.base.ClaimPolicy;
import com.webank.weid.protocol.base.Cpt;
import com.webank.weid.protocol.base.CptBaseInfo;
import com.webank.weid.protocol.base.PresentationPolicyE;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.request.CptMapArgs;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.protocol.response.RsvSignature;
import com.webank.weid.rpc.PolicyService;
import com.webank.weid.util.CredentialPojoUtils;
import com.webank.weid.util.DataToolUtils;
import com.webank.weid.util.WeIdUtils;

/**
 * Service implementations for operations on Evidence.
 *
 * @author chaoxinhu 2020.8
 */

public class PolicyServiceImpl extends AbstractService implements PolicyService {

    private static final Logger logger = LoggerFactory.getLogger(PolicyServiceImpl.class);

    /**
     * Register Claim Policy on blockchain and assign it under a CPT ID.
     *
     * @param cptId CPT ID
     * @param policyJson Policy Json file
     * @param weIdAuthentication WeID auth
     * @return claimPolicyId the Claim policy ID on-chain
     */
    @Override
    public ResponseData<Integer> registerClaimPolicy(Integer cptId, String policyJson,
        WeIdAuthentication weIdAuthentication) {
        ResponseData<Integer> policyIdResp = registerPolicyData(policyJson, weIdAuthentication);
        if (policyIdResp.getResult() < 0) {
            logger.error("Failed to register Claim Policy to blockchain.");
            return policyIdResp;
        }
        // Append this claim policy id to the existing CPT's list
        ResponseData<List<Integer>> policiesResp = getClaimPoliciesFromCpt(cptId);
        if (policiesResp.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
            logger.error("Failed to get this CPT's claim policy list.");
            return new ResponseData<>(-1, policiesResp.getErrorCode(),
                policiesResp.getErrorMessage());
        }
        List<Integer> policies = policiesResp.getResult();
        if (CollectionUtils.isEmpty(policies)) {
            policies = new ArrayList<>();
        }
        policies.add(policyIdResp.getResult());
        ResponseData<Integer> addResp = cptServiceEngine
            .putPolicyIntoCpt(cptId, policies, weIdAuthentication.getWeIdPrivateKey());
        if (addResp.getResult() < 0) {
            logger.error("Failed to add this policy ID {} into existing CPT ID's list: {}",
                policyIdResp.getResult(), cptId);
            return addResp;
        }
        return new ResponseData<>(policyIdResp.getResult(), ErrorCode.SUCCESS);
    }

    private ResponseData<Integer> registerPolicyData(String policyJson, WeIdAuthentication auth) {
        if (!DataToolUtils.isValidJsonStr(policyJson)) {
            logger.error("[registerPolicy] input json format illegal.");
            return new ResponseData<>(null, ErrorCode.CPT_JSON_SCHEMA_INVALID);
        }
        ErrorCode errorCode = CredentialPojoUtils.isWeIdAuthenticationValid(auth);
        if (errorCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(-1, errorCode);
        }
        CptMapArgs cptMapArgs = new CptMapArgs();
        cptMapArgs.setWeIdAuthentication(auth);
        Map<String, Object> cptJsonSchemaMap = DataToolUtils.deserialize(policyJson, HashMap.class);
        cptMapArgs.setCptJsonSchema(cptJsonSchemaMap);
        WeIdPrivateKey weIdPrivateKey = auth.getWeIdPrivateKey();
        String cptJsonSchemaNew = DataToolUtils.serialize(cptMapArgs.getCptJsonSchema());
        RsvSignature rsvSignature = sign(
            auth.getWeId(),
            cptJsonSchemaNew,
            weIdPrivateKey);
        String address = WeIdUtils.convertWeIdToAddress(auth.getWeId());
        CptBaseInfo cptBaseInfo;
        try {
            cptBaseInfo = cptServiceEngine.registerCpt(address, cptJsonSchemaNew, rsvSignature,
                weIdPrivateKey, WeIdConstant.POLICY_DATA_INDEX).getResult();
        } catch (Exception e) {
            logger.error("[register policy] register failed due to unknown error. ", e);
            return new ResponseData<>(-1, ErrorCode.UNKNOW_ERROR.getCode(),
                ErrorCode.UNKNOW_ERROR.getCodeDesc() + e.getMessage());
        }
        if (cptBaseInfo != null && cptBaseInfo.getCptId() > 0) {
            return new ResponseData<>(cptBaseInfo.getCptId(), ErrorCode.SUCCESS);
        } else {
            return new ResponseData<>(-1, ErrorCode.UNKNOW_ERROR);
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
            sb.toString(), cptPublisherPrivateKey);
        return DataToolUtils.convertSignatureDataToRsv(signatureData);
    }

    /**
     * Get Claim Policy Json from blockchain given a policy ID.
     *
     * @param policyId the Claim Policy ID on-chain
     * @return the claim Json
     */
    @Override
    public ResponseData<ClaimPolicy> getClaimPolicy(Integer policyId) {
        if (policyId == null || policyId < 0) {
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        ResponseData<Cpt> policyResp = cptServiceEngine
            .queryCpt(policyId, WeIdConstant.POLICY_DATA_INDEX);
        if (policyResp.getResult() == null) {
            return new ResponseData<>(null, ErrorCode.CPT_NOT_EXISTS.getCode(),
                ErrorCode.CPT_NOT_EXISTS.getCodeDesc() + policyResp.getErrorMessage());
        }
        ClaimPolicy claimPolicy = new ClaimPolicy();
        claimPolicy.setFieldsToBeDisclosed(
            DataToolUtils.serialize(policyResp.getResult().getCptJsonSchema()));
        return new ResponseData<>(claimPolicy, ErrorCode.SUCCESS);
    }

    /**
     * Get all claim policies from this CPT ID.
     *
     * @param cptId cpt id
     * @return claim policies list
     */
    @Override
    public ResponseData<List<Integer>> getClaimPoliciesFromCpt(Integer cptId) {
        if (cptId == null || cptId < 0) {
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        return cptServiceEngine.getPolicyFromCpt(cptId);
    }

    /**
     * Register Presentation Policy which contains a number of claim policies.
     *
     * @param claimPolicyIdList claim policies list
     * @param weIdAuthentication weid auth
     * @return the presentation policy id
     */
    @Override
    public ResponseData<Integer> registerPresentationPolicy(List<Integer> claimPolicyIdList,
        WeIdAuthentication weIdAuthentication) {
        ErrorCode errorCode = CredentialPojoUtils.isWeIdAuthenticationValid(weIdAuthentication);
        if (errorCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(-1, errorCode);
        }
        return cptServiceEngine
            .putPolicyIntoPresentation(claimPolicyIdList, weIdAuthentication.getWeIdPrivateKey());
    }

    /**
     * Get Presentation policies under this id from chain.
     *
     * @param presentationPolicyId presentation policy id
     * @return the full presentation policy
     */
    @Override
    public ResponseData<PresentationPolicyE> getPresentationPolicy(Integer presentationPolicyId) {
        if (presentationPolicyId == null || presentationPolicyId < 0) {
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        PresentationPolicyE presentationPolicy = cptServiceEngine
            .getPolicyFromPresentation(presentationPolicyId)
            .getResult();
        if (presentationPolicy == null) {
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_CLAIM_POLICY_NOT_EXIST);
        }
        Map<Integer, ClaimPolicy> policyMap = new HashMap<>();
        for (Map.Entry<Integer, ClaimPolicy> entry : presentationPolicy.getPolicy().entrySet()) {
            policyMap.put(entry.getKey(), getClaimPolicy(entry.getKey()).getResult());
        }
        presentationPolicy.setPolicy(policyMap);
        return new ResponseData<>(presentationPolicy, ErrorCode.SUCCESS);
    }


    /**
     * Get all claim policies from chain.
     *
     * @param startPos start position
     * @param num batch number
     * @return claim policy list
     */
    @Override
    public ResponseData<List<Integer>> getAllClaimPolicies(Integer startPos, Integer num) {
        if (startPos < 0 || num < 1) {
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        return cptServiceEngine.getCptLists(startPos, num, WeIdConstant.POLICY_DATA_INDEX);
    }
}
