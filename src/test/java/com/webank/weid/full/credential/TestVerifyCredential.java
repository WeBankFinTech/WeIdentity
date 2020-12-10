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

package com.webank.weid.full.credential;

import java.util.Map;

import mockit.Mock;
import mockit.MockUp;
import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.webank.weid.util.CredentialUtils.copyCredential;

import com.webank.weid.common.LogUtil;
import com.webank.weid.common.PasswordKey;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.ParamKeyConstant;
import com.webank.weid.full.TestBaseService;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.CptBaseInfo;
import com.webank.weid.protocol.base.Credential;
import com.webank.weid.protocol.base.CredentialWrapper;
import com.webank.weid.protocol.base.WeIdDocument;
import com.webank.weid.protocol.request.CreateCredentialArgs;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.service.impl.WeIdServiceImpl;

/**
 * verifyCredential method for testing CredentialService.
 *
 * @author v_wbgyang
 */
public class TestVerifyCredential extends TestBaseService {

    private static final Logger logger = LoggerFactory.getLogger(TestVerifyCredential.class);

    protected PasswordKey passwordKey = null;

    private static Credential credential = null;

    @Override
    public synchronized void testInit() {
        super.testInit();
        passwordKey = TestBaseUtil.createEcKeyPair();
        if (credential == null) {
            credential = super.createCredential(createCredentialArgs).getCredential();
        }
    }

    /**
     * case: verifyCredential success.
     */
    @Test
    public void testVerifyCredential_success() {

        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());
    }


    /**
     * case: context is null.
     */
    @Test
    public void testVerifyCredential_contextNull() {

        String context = credential.getContext();
        credential.setContext(null);
        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        credential.setContext(context);
        Assert.assertEquals(ErrorCode.CREDENTIAL_CONTEXT_NOT_EXISTS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: context is other string.
     */
    @Test
    public void testVerifyCredential_contentIsOtherString() {

        String context = credential.getContext();
        credential.setContext("xxx");

        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        credential.setContext(context);
        Assert.assertEquals(ErrorCode.CREDENTIAL_VERIFY_FAIL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: context contain special char.
     */
    // CI hold: @Test
    public void testVerifyCredential_contentContainSpecialChar() {

        String context = credential.getContext();
        credential.setContext("xxx！@#￥%……&*（）KL14536987");

        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        credential.setContext(context);
        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUER_MISMATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: cptId is another with **same** schema.
     */
    @Test
    public void testVerifyCredential_cptIdAndClaimDifferent() {

        Integer cptId = credential.getCptId();
        CptBaseInfo cpt = super.registerCpt(createWeIdResultWithSetAttr, registerCptArgs);
        credential.setCptId(cpt.getCptId());

        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        credential.setCptId(cptId);
        Assert.assertEquals(ErrorCode.CREDENTIAL_VERIFY_FAIL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: cptId is another with **same** schema.
     */
    @Test
    public void testVerifyCredential_cptIdNull() {

        Integer cptId = credential.getCptId();
        credential.setCptId(null);

        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        credential.setCptId(cptId);
        Assert.assertEquals(ErrorCode.CPT_ID_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: id is null.
     */
    @Test
    public void testVerifyCredential_idNull() {

        String id = credential.getId();
        credential.setId(null);

        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        credential.setId(id);
        Assert.assertEquals(ErrorCode.CREDENTIAL_ID_NOT_EXISTS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: id is another.
     */
    @Test
    public void testVerifyCredential_otherId() {

        String id = credential.getId();
        credential.setId("xxxxxxxxx");
        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        credential.setId(id);
        Assert.assertEquals(ErrorCode.CREDENTIAL_ID_NOT_EXISTS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: issuer is null.
     */
    @Test
    public void testVerifyCredentialCase10() {

        String issuer = credential.getIssuer();
        credential.setIssuer(null);

        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        credential.setIssuer(issuer);
        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUER_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: issuer is xxxxx.
     */
    @Test
    public void testVerifyCredential_invalidIssuer() {

        String issuer = credential.getIssuer();
        credential.setIssuer("xxxxxxxxxxx");

        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        credential.setIssuer(issuer);
        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUER_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: issuer is another.
     */
    @Test
    public void testVerifyCredential_otherIssuer() {

        String issuer = credential.getIssuer();
        credential.setIssuer(createWeIdNew.getWeId());

        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        credential.setIssuer(issuer);
        Assert.assertEquals(ErrorCode.CREDENTIAL_VERIFY_FAIL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: IssuanceDate < = 0.
     */
    @Test
    public void testVerifyCredentialCase13() {

        Long issuanceDate = credential.getIssuanceDate();
        credential.setIssuanceDate(-1L);

        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        credential.setIssuanceDate(issuanceDate);
        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUANCE_DATE_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: IssuanceDate > now.
     */
    @Test
    public void testVerifyCredentialCase14() {

        Long issuanceDate = credential.getIssuanceDate();
        credential.setIssuanceDate(System.currentTimeMillis() + 100000);

        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        credential.setIssuanceDate(issuanceDate);
        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUANCE_DATE_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: expirationDate <= 0.
     */
    @Test
    public void testVerifyCredentialCase15() {

        Long expirationDate = credential.getExpirationDate();
        credential.setExpirationDate(-1L);
        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        credential.setExpirationDate(expirationDate);
        Assert.assertEquals(ErrorCode.CREDENTIAL_EXPIRE_DATE_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: expirationDate <= now.
     */
    @Test
    public void testVerifyCredentialCase16() {

        Long expirationDate = credential.getExpirationDate();
        credential.setExpirationDate(credential.getIssuanceDate() - 100000000);
        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        credential.setExpirationDate(expirationDate);
        Assert.assertEquals(ErrorCode.CREDENTIAL_EXPIRED.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: expirationDate is null.
     */
    @Test
    public void testVerifyCredentialCase17() {

        Long expirationDate = credential.getExpirationDate();
        credential.setExpirationDate(null);
        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        credential.setExpirationDate(expirationDate);
        Assert.assertEquals(ErrorCode.CREDENTIAL_EXPIRE_DATE_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: IssuanceDate is null.
     */
    @Test
    public void testVerifyCredentialCase18() {

        Long issuanceDate = credential.getIssuanceDate();
        credential.setIssuanceDate(null);
        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        credential.setIssuanceDate(issuanceDate);
        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUANCE_DATE_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: claim is null. test error,Please add check.
     */
    // @Test
    public void testVerifyCredential_claimNull() {

        Map<String, Object> claim = credential.getClaim();
        credential.setClaim(null);
        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        credential.setClaim(claim);
        Assert.assertEquals(ErrorCode.CREDENTIAL_CLAIM_NOT_EXISTS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: signature is empty.
     */
    @Test
    public void testVerifyCredentialCase21() {
        Credential newCredential = copyCredential(credential);
        Map<String, String> proof = newCredential.getProof();
        proof.put(ParamKeyConstant.CREDENTIAL_SIGNATURE, StringUtils.EMPTY);
        newCredential.setProof(proof);

        ResponseData<Boolean> response = super.verifyCredential(newCredential);
        LogUtil.info(logger, "verifyCredential", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_SIGNATURE_BROKEN.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: signature is null.
     */
    @Test
    public void testVerifyCredentialCase22() {
        Credential newCredential = copyCredential(credential);
        Map<String, String> proof = newCredential.getProof();
        proof.put(ParamKeyConstant.CREDENTIAL_SIGNATURE, null);
        newCredential.setProof(proof);

        ResponseData<Boolean> response = super.verifyCredential(newCredential);
        LogUtil.info(logger, "verifyCredential", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_SIGNATURE_BROKEN.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: signature is xxxxxxxxxxxxxxxxxxx.
     */
    @Test
    public void testVerifyCredentialCase23() {

        Credential newCredential = copyCredential(credential);
        Map<String, String> proof = newCredential.getProof();
        proof.put(ParamKeyConstant.CREDENTIAL_SIGNATURE, "xxxxxxxxxxx");
        newCredential.setProof(proof);

        ResponseData<Boolean> response = super.verifyCredential(newCredential);
        LogUtil.info(logger, "verifyCredential", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_SIGNATURE_BROKEN.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: signature by 122324324324.
     */
    @Test
    public void testVerifyCredentialCase24() {

        CreateCredentialArgs createCredentialArgs =
            TestBaseUtil.buildCreateCredentialArgs(createWeIdResultWithSetAttr);
        createCredentialArgs.setCptId(cptBaseInfo.getCptId());

        createCredentialArgs.getWeIdPrivateKey().setPrivateKey("122324324324");

        CredentialWrapper credentialWrapper = super.createCredential(createCredentialArgs);
        ResponseData<Boolean> response = super.verifyCredential(credentialWrapper.getCredential());
        LogUtil.info(logger, "verifyCredential", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_VERIFY_FAIL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }


    /**
     * case: Sing through another private key in publickeys of WeIdentity DID.
     */
    // CI hold: @Test
    public void testVerifyCredentialCase26() {

        super.setPublicKey(
            createWeIdResultWithSetAttr,
            passwordKey.getPublicKey(),
            createWeIdResultWithSetAttr.getWeId());
        super.setAuthentication(
            createWeIdResultWithSetAttr,
            passwordKey.getPublicKey(),
            createWeIdResultWithSetAttr.getWeId());

        CreateCredentialArgs createCredentialArgs =
            TestBaseUtil.buildCreateCredentialArgs(createWeIdResultWithSetAttr);
        createCredentialArgs.setCptId(cptBaseInfo.getCptId());

        createCredentialArgs.getWeIdPrivateKey().setPrivateKey(passwordKey.getPrivateKey());
        CredentialWrapper credentialWrapper = super.createCredential(createCredentialArgs);
        ResponseData<Boolean> response = super.verifyCredential(credentialWrapper.getCredential());
        LogUtil.info(logger, "verifyCredential", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());
    }

    /**
     * case: IssuanceDate < now && expirationDate < now  && IssuanceDate < expirationDate.
     */
    @Test
    public void testVerifyCredentialCase27() {

        Long issuanceDate = credential.getIssuanceDate();
        Long expirationDate = credential.getExpirationDate();
        credential.setIssuanceDate(System.currentTimeMillis() - 12000);
        credential.setExpirationDate(System.currentTimeMillis() - 10000);
        ResponseData<Boolean> response = super.verifyCredential(credential);
        credential.setIssuanceDate(issuanceDate);
        credential.setExpirationDate(expirationDate);
        LogUtil.info(logger, "verifyCredential", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_EXPIRED.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: mock CREDENTIAL_WEID_DOCUMENT_ILLEGAL.
     */
    @Test
    public void testVerifyCredentialCase28() {

        new MockUp<WeIdServiceImpl>() {
            @Mock
            public ResponseData<WeIdDocument> getWeIdDocument(String weId) {
                ResponseData<WeIdDocument> response = new ResponseData<WeIdDocument>();
                response.setErrorCode(ErrorCode.CREDENTIAL_WEID_DOCUMENT_ILLEGAL);
                return response;
            }
        };

        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_WEID_DOCUMENT_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: proof creator and created are null - this is OK.
     */
    @Test
    public void testVerifyCredentialCase29() {

        Credential newCredential = copyCredential(credential);
        Map<String, String> proof = newCredential.getProof();
        proof.put(ParamKeyConstant.PROOF_CREATOR, null);
        newCredential.setProof(proof);

        ResponseData<Boolean> response = super.verifyCredential(newCredential);
        LogUtil.info(logger, "verifyCredential", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());
    }

    /**
     * case: issuer is not exists.
     */
    @Test
    public void testVerifyCredentialCase30() {

        String issuer = credential.getIssuer();
        credential.setIssuer("did:weid:0xbb1670306aedfaeb75cff9581c99e56ba4797441");

        ResponseData<Boolean> response = super.verifyCredential(credential);
        LogUtil.info(logger, "verifyCredential", response);

        credential.setIssuer(issuer);
        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUER_NOT_EXISTS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: proof type illegal.
     */
    @Test
    public void testVerifyCredentialCase31() {

        Credential newCredential = copyCredential(credential);
        Map<String, String> proof = newCredential.getProof();
        proof.put(ParamKeyConstant.PROOF_TYPE, null);
        newCredential.setProof(proof);

        ResponseData<Boolean> response = super.verifyCredential(newCredential);
        LogUtil.info(logger, "verifyCredential", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_SIGNATURE_TYPE_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: proof is missing signature key at all - fail.
     */
    @Test
    public void testVerifyCredentialCase32() {

        Credential newCredential = copyCredential(credential);
        Map<String, String> proof = newCredential.getProof();
        proof.remove(ParamKeyConstant.CREDENTIAL_SIGNATURE);
        newCredential.setProof(proof);

        ResponseData<Boolean> response = super.verifyCredential(newCredential);
        LogUtil.info(logger, "verifyCredential", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_SIGNATURE_BROKEN.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(false, response.getResult());
    }

    /**
     * case: proof is missing creator key at all - should be fine.
     */
    // CI hold: @Test
    public void testVerifyCredentialCase33() {

        Credential newCredential = copyCredential(credential);
        Map<String, String> proof = newCredential.getProof();
        proof.remove(ParamKeyConstant.PROOF_CREATOR);
        newCredential.setProof(proof);

        ResponseData<Boolean> response = super.verifyCredential(newCredential);
        LogUtil.info(logger, "verifyCredential", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());
    }
}
