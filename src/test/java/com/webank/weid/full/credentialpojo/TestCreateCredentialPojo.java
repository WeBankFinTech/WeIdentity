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

package com.webank.weid.full.credentialpojo;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.fisco.bcos.sdk.crypto.keypair.CryptoKeyPair;
import org.fisco.bcos.sdk.utils.Numeric;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.common.PasswordKey;
import com.webank.weid.constant.CredentialConstant;
import com.webank.weid.constant.CredentialType;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.full.TestBaseService;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.CptBaseInfo;
import com.webank.weid.protocol.base.CredentialPojo;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.cpt.Cpt101;
import com.webank.weid.protocol.request.AuthenticationArgs;
import com.webank.weid.protocol.request.CptStringArgs;
import com.webank.weid.protocol.request.CreateCredentialPojoArgs;
import com.webank.weid.protocol.request.CreateWeIdArgs;
import com.webank.weid.protocol.request.SetAuthenticationArgs;
import com.webank.weid.protocol.request.SetPublicKeyArgs;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.util.CredentialPojoUtils;
import com.webank.weid.util.DataToolUtils;
import com.webank.weid.util.DateUtils;
import com.webank.weid.util.WeIdUtils;

/**
 * createCredential method for testing CredentialService.
 *
 * @author v_wbgyang
 */
public class TestCreateCredentialPojo extends TestBaseService {

    private static final Logger logger = LoggerFactory.getLogger(TestCreateCredentialPojo.class);

    @Override
    public synchronized void testInit() {

        super.testInit();
        if (cptBaseInfo == null) {
            cptBaseInfo = super.registerCpt(createWeIdResultWithSetAttr);
            Assert.assertTrue(cptBaseInfo.getCptId() > 2000000);
        }
    }

    /**
     * case：when issuer and cpt publisher is same,createCredentialPojo success.
     */
    @Test
    public void testCreateCredentialPojo_success() {

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        ResponseData<Boolean> verify = credentialPojoService.verify(
            createCredentialPojoArgs.getIssuer(), response.getResult());
        Assert.assertTrue(verify.getResult());
    }

    @Test
    public void testCreateCredentialPojoWithOtherWeIdAndRevocation_success() {
        CreateWeIdDataResult cwdr = createWeIdWithSetAttr();
        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        createCredentialPojoArgs.setIssuer(cwdr.getWeId());
        WeIdAuthentication weIdAuth = new WeIdAuthentication();
        weIdAuth.setWeId(cwdr.getWeId());

        // Add new public key to this guy
        PasswordKey pwKey = TestBaseUtil.createEcKeyPair();
        AuthenticationArgs arg = new AuthenticationArgs();
        arg.setOwner(cwdr.getWeId());
        arg.setPublicKey(pwKey.getPublicKey());
        ResponseData<Boolean> addResp = weIdService.setAuthentication(cwdr.getWeId(),
            arg, cwdr.getUserWeIdPrivateKey());
        System.out.println(weIdService.getWeIdDocumentJson(cwdr.getWeId()));

        // Using the new private key to sign credential
        WeIdPrivateKey weIdPrivateKey = new WeIdPrivateKey();
        weIdPrivateKey.setPrivateKey(pwKey.getPrivateKey());
        weIdAuth.setWeIdPrivateKey(weIdPrivateKey);
        weIdAuth.setWeIdPublicKeyId(cwdr.getUserWeIdPublicKey().getPublicKey() + "#keys-1");
        createCredentialPojoArgs.setWeIdAuthentication(weIdAuth);

        ResponseData<CredentialPojo> createResp =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", createResp);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), createResp.getErrorCode().intValue());

        // Verify this is OK
        ResponseData<Boolean> verify = credentialPojoService.verify(
            createCredentialPojoArgs.getIssuer(), createResp.getResult());
        Assert.assertTrue(verify.getResult());

        // Specify key ID to be "1" and it should be OK too
        verify = credentialPojoService.verify(createCredentialPojoArgs.getIssuer(),
            "1", createResp.getResult());
        Assert.assertTrue(verify.getResult());

        // Specify key ID to be "0" and it should be semi-succeeded
        verify = credentialPojoService.verify(createCredentialPojoArgs.getIssuer(),
            "0", createResp.getResult());
        Assert.assertFalse(verify.getResult());
        Assert.assertEquals(verify.getErrorCode().intValue(),
            ErrorCode.CREDENTIAL_VERIFY_SUCCEEDED_WITH_WRONG_PUBLIC_KEY_ID.getCode());

    }

    /**
     * Test timestamp services.
     */
    // NOTE: TODO when doing any local tests, please make sure this is enabled.
    // This test is prohibited in CI workflow to reduce WeSign costs.
    // @Test
    public void testCreateAndVerifyTimestamp() {
        // Happy path
        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(response.getResult());
        WeIdAuthentication callerAuth = TestBaseUtil
            .buildWeIdAuthentication(createWeIdResultWithSetAttr);
        ResponseData<CredentialPojo> resp = credentialPojoService
            .createTrustedTimestamp(credPojoList, callerAuth);
        CredentialPojo tscred = resp.getResult();
        Assert.assertNotNull(tscred);
        System.out.println(DataToolUtils.serialize(tscred));
        ResponseData<Boolean> respData = credentialPojoService.verify(tscred.getIssuer(), tscred);
        Assert.assertTrue(respData.getResult());

        // Modify timestamp then..
        CredentialPojo modifiedTsCred = copyCredentialPojo(tscred);
        Map<String, Object> claim = modifiedTsCred.getClaim();
        String tstamp = (String) claim.get("authoritySignature");
        claim.put("authoritySignature", tstamp + "a");
        modifiedTsCred.setClaim(claim);
        respData = credentialPojoService.verify(modifiedTsCred.getIssuer(), modifiedTsCred);
        Assert.assertFalse(respData.getResult());
        Assert.assertEquals(respData.getErrorCode().intValue(),
            ErrorCode.TIMESTAMP_VERIFICATION_FAILED.getCode());
        modifiedTsCred = copyCredentialPojo(tscred);
        claim = modifiedTsCred.getClaim();
        Long stamptime = (long) claim.get("timestamp");
        claim.put("timestamp", stamptime - 100);
        modifiedTsCred.setClaim(claim);
        respData = credentialPojoService.verify(modifiedTsCred.getIssuer(), modifiedTsCred);
        Assert.assertFalse(respData.getResult());
        Assert.assertEquals(respData.getErrorCode().intValue(),
            ErrorCode.TIMESTAMP_VERIFICATION_FAILED.getCode());

        // SD credential should fail.
        credPojoList = new ArrayList<>();
        credPojoList.add(credentialPojo);
        credPojoList.add(selectiveCredentialPojo);
        resp = credentialPojoService.createTrustedTimestamp(credPojoList, callerAuth);
        Assert.assertNull(resp.getResult());
        Assert.assertEquals(resp.getErrorCode().intValue(),
            ErrorCode.TIMESTAMP_CREATION_FAILED_FOR_SELECTIVELY_DISCLOSED.getCode());
    }

    /**
     * case：when issuer and cpt publisher is same,createCredentialPojo success.
     */
    @Test
    public void testCreateMultiSignCredentialPojo_success() {

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        ResponseData<CredentialPojo> credResp1 =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", credResp1);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), credResp1.getErrorCode().intValue());
        ResponseData<Boolean> verify = credentialPojoService.verify(
            createCredentialPojoArgs.getIssuer(), credResp1.getResult());
        Assert.assertTrue(verify.getResult());

        CreateWeIdDataResult weIdResult2 = createWeIdWithSetAttr();
        createCredentialPojoArgs = TestBaseUtil.buildCreateCredentialPojoArgs(weIdResult2);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        Long expirationDate = DateUtils.convertToNoMillisecondTimeStamp(
            createCredentialPojoArgs.getExpirationDate() + 24 * 60 * 60);
        createCredentialPojoArgs.setExpirationDate(expirationDate);
        ResponseData<CredentialPojo> credResp2 =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", credResp2);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), credResp2.getErrorCode().intValue());
        verify = credentialPojoService.verify(
            createCredentialPojoArgs.getIssuer(), credResp2.getResult());
        Assert.assertTrue(verify.getResult());

        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(credResp1.getResult());
        credPojoList.add(credResp2.getResult());
        CreateWeIdDataResult weIdResult3 = createWeIdWithSetAttr();
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weIdResult3);
        CredentialPojo doubleSigned = credentialPojoService.addSignature(credPojoList, callerAuth)
            .getResult();
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);
        Assert.assertEquals(doubleSigned.getExpirationDate(), expirationDate);
        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        Assert.assertTrue(verifyResp.getResult());
        credPojoList = new ArrayList<>();
        credPojoList.add(doubleSigned);
        CredentialPojo tripleSigned = credentialPojoService.addSignature(credPojoList, callerAuth)
            .getResult();
        verifyResp = credentialPojoService.verify(doubleSigned.getIssuer(), tripleSigned);
        Assert.assertTrue(verifyResp.getResult());
    }

    /**
     * case：when issuer and cpt publisher is same,createCredentialPojo success.
     */
    @Test
    public void testCreateMultiSignCredentialPojo_failure() {

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        ResponseData<CredentialPojo> credResp1 =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", credResp1);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), credResp1.getErrorCode().intValue());
        ResponseData<Boolean> verify = credentialPojoService.verify(
            createCredentialPojoArgs.getIssuer(), credResp1.getResult());
        Assert.assertTrue(verify.getResult());

        CreateWeIdDataResult weIdResult2 = createWeIdWithSetAttr();
        createCredentialPojoArgs = TestBaseUtil.buildCreateCredentialPojoArgs(weIdResult2);
        createCredentialPojoArgs.setCptId(10);
        Long expirationDate = DateUtils.convertToNoMillisecondTimeStamp(
            createCredentialPojoArgs.getExpirationDate() + 24 * 60 * 60);
        createCredentialPojoArgs.setExpirationDate(expirationDate);
        ResponseData<CredentialPojo> credResp2 =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", credResp2);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), credResp2.getErrorCode().intValue());
        verify = credentialPojoService.verify(
            createCredentialPojoArgs.getIssuer(), credResp2.getResult());
        Assert.assertFalse(verify.getResult());

        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(credResp1.getResult());
        credPojoList.add(credResp2.getResult());
        CreateWeIdDataResult weIdResult3 = createWeIdWithSetAttr();
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weIdResult3);
        CredentialPojo doubleSigned = credentialPojoService.addSignature(credPojoList, callerAuth)
            .getResult();
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);
        Assert.assertEquals(doubleSigned.getExpirationDate(), expirationDate);
        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        Assert.assertFalse(verifyResp.getResult());
        credPojoList = new ArrayList<>();
        credPojoList.add(doubleSigned);
        CredentialPojo tripleSigned = credentialPojoService.addSignature(credPojoList, callerAuth)
            .getResult();
        verifyResp = credentialPojoService.verify(tripleSigned.getIssuer(), tripleSigned);
        Assert.assertFalse(verifyResp.getResult());
    }

    @Test
    public void testLiteCredentialPojo() {
        CreateWeIdDataResult createWeIdDataResult = super.createWeId();
        CreateCredentialPojoArgs<Map<String, Object>> args =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdDataResult);
        args.setType(CredentialType.LITE1);
        args.setCptId(cptBaseInfo.getCptId());
        ResponseData<CredentialPojo> response = credentialPojoService.createCredential(args);
        LogUtil.info(logger, "createLiteCredential", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        CredentialPojo liteCredential = response.getResult();
        ResponseData<Boolean> resp =
            credentialPojoService.verify(liteCredential.getIssuer(), liteCredential);
        Assert.assertTrue(resp.getResult());
        // String recovererdWeId = DataToolUtils.recoverWeIdFromMsgAndSecp256Sig(
        //    CredentialPojoUtils.getLiteCredentialThumbprintWithoutSig(liteCredential),
        //    liteCredential.getSignature());
        // Assert.assertEquals(recovererdWeId, liteCredential.getIssuer());

        // LiteCredential:
        // 1. getThumbprint() -> signature (针对凭证claim内容生成thumbprint，用私钥生成签名)
        String thumbprint = CredentialPojoUtils
            .getLiteCredentialThumbprintWithoutSig(liteCredential);
        System.out.println("Lite Credential Thumbprint: " + thumbprint + ", Thumbprint hash: "
            + DataToolUtils.sha3(thumbprint) + ", signature: " + liteCredential.getSignature());
        // 2. getHash() -> createEvidence (对凭证完整内容包括签名内容进行hash，claim支持选择性披露)
        System.out.println("Lite Credential Hash: "
            + CredentialPojoUtils.getLiteCredentialPojoHash(liteCredential));
        Assert.assertEquals(CredentialPojoUtils.getLiteCredentialPojoHash(liteCredential),
            liteCredential.getHash());
        // 3. toJson() -> encrypt (唯一的序列化方法，瘦身，用于打包传输)
        System.out.println("Lite Credential toJson: " + liteCredential.toJson());

        // Original CredentialPojo:
        CredentialPojo tempCredential = copyCredentialPojo(credentialPojo);
        thumbprint = CredentialPojoUtils.getCredentialThumbprintWithoutSig(tempCredential,
            tempCredential.getSalt(), null);
        System.out.println("Original Credential Thumbprint: " + thumbprint);
        System.out.println("Original Credential Hash: "
            + CredentialPojoUtils.getCredentialPojoHash(tempCredential, null));
        System.out.println("Original Credential toJson: " + tempCredential.toJson());

        // Original SD CredentialPojo:
        CredentialPojo tempSdCredential = copyCredentialPojo(selectiveCredentialPojo);
        thumbprint = CredentialPojoUtils.getCredentialThumbprintWithoutSig(tempSdCredential,
            tempSdCredential.getSalt(), null);
        System.out.println("Original SD Credential Thumbprint: " + thumbprint);
        System.out.println("Original SD Credential Hash: "
            + CredentialPojoUtils.getCredentialPojoHash(tempSdCredential, null));
        System.out.println("Original SD Credential toJson: " + tempSdCredential.toJson());
    }

    /**
     * case：when issuer is register authentication issuer, cpt publisher is not auth issuer,
     * createCredentialPojo success.
     */
    @Test
    public void testCreateCredentialPojo_authenticationIssuerSuccess() {

        CreateWeIdDataResult createWeIdDataResult = super.createWeId();
        super.registerAuthorityIssuer(createWeIdDataResult);
        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdDataResult);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        ResponseData<Boolean> verify = credentialPojoService.verify(
            createCredentialPojoArgs.getIssuer(), response.getResult());
        Assert.assertTrue(verify.getResult());
    }

    /**
     * case：cpt publisher is auth issuer, createCredentialPojo success.
     */
    @Test
    public void testCreateCredentialPojo_authenticationCptSuccess() {

        CreateWeIdDataResult createWeIdDataResult = super.createWeId();
        super.registerAuthorityIssuer(createWeIdDataResult);
        authorityIssuerService.recognizeAuthorityIssuer(createWeIdDataResult.getWeId(),
            new WeIdPrivateKey(privateKey));
        CptBaseInfo cptBaseInfo = super.registerCpt(createWeIdDataResult);
        Assert.assertTrue(cptBaseInfo.getCptId() < 2000000);

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        ResponseData<Boolean> verify = credentialPojoService.verify(
            createCredentialPojoArgs.getIssuer(), response.getResult());
        Assert.assertTrue(verify.getResult());
    }

    /**
     * case：repeat createCredentialPojo success.
     */
    @Test
    public void testCreateCredentialPojo_repeatSuccess() {

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());

        ResponseData<CredentialPojo> response1 =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response1);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response1.getErrorCode().intValue());
        Assert.assertNotNull(response1.getResult());
    }

    /**
     * case：createCredential success refer to doc.
     */
    @Test
    public void testCreateCredentialPojo_sampleFail() {

        HashMap<String, Object> claim = new HashMap<>();
        claim.put("student", new CptBaseInfo());
        claim.put("name", "李白");
        claim.put("age", 1300);
        claim.put("poiet", "桃花潭水深千尺，不及汪伦送我情");
        CreateCredentialPojoArgs createCredentialArgs = new CreateCredentialPojoArgs();
        createCredentialArgs.setClaim(claim);

        createCredentialArgs.setCptId(cptBaseInfo.getCptId());
        createCredentialArgs.setExpirationDate(System.currentTimeMillis() + 6000);
        createCredentialArgs.setIssuer(createWeIdResultWithSetAttr.getWeId());

        WeIdAuthentication weIdAuthentication = new WeIdAuthentication();
        weIdAuthentication.setWeId(createWeIdResultWithSetAttr.getWeId());
        weIdAuthentication.setWeIdPublicKeyId(
            createWeIdResultWithSetAttr.getUserWeIdPublicKey().getPublicKey());
        weIdAuthentication.setWeIdPrivateKey(
            createWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        createCredentialArgs.setWeIdAuthentication(weIdAuthentication);

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        ResponseData<Boolean> verify = credentialPojoService.verify(
            createCredentialArgs.getIssuer(), response.getResult());
        LogUtil.info(logger, "verify", verify);
        Assert.assertEquals(
            ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL.getCode(), verify.getErrorCode().intValue());
        Assert.assertFalse(verify.getResult());
    }

    /**
     * case：when weIdAuthentication is null,createCredentialPojo return ILLEGAL_INPUT.
     */
    @Test
    public void testCreateCredentialPojo_weIdAuthenticationNull() {

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        createCredentialPojoArgs.setWeIdAuthentication(new WeIdAuthentication());

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case: createCredentialPojoArgs is null,return ILLEGAL_INPUT.
     */
    @Test
    public void testCreateCredentialPojo_credentialArgsNull() {

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(null);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case：cptId is null,return ILLEGAL_INPUT .
     */
    @Test
    public void testCreateCredential_cptIdNull() {

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.CPT_ID_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptId is minus number,return CREDENTIAL_CPT_NOT_EXISTS.
     */
    @Test
    public void testCreateCredential_cptIdMinus() {

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(-1);

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.CPT_ID_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
    }

    /**
     * case： cptId is not exists,createCredentialPojo success but verify fail.
     */
    @Test
    public void testCreateCredential_cptIdNotExist() {

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(999999999);

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(),
            response.getErrorCode().intValue());

        ResponseData<Boolean> verify = credentialPojoService.verify(
            createCredentialPojoArgs.getIssuer(), response.getResult());
        LogUtil.info(logger, "verify createCredentialPojo", verify);
        Assert.assertEquals(ErrorCode.CREDENTIAL_CPT_NOT_EXISTS.getCode(),
            verify.getErrorCode().intValue());
        Assert.assertFalse(verify.getResult());
    }

    /**
     * case： cptId is belongs to others weIdentity dId.
     */
    @Test
    public void testCreateCredential_otherCptIdSuccess() {

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        CptBaseInfo cptBaseInfoNew = super.registerCpt(createWeIdNew);
        createCredentialPojoArgs.setCptId(cptBaseInfoNew.getCptId());

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        ResponseData<Boolean> verify = credentialPojoService.verify(
            createCredentialPojoArgs.getIssuer(), response.getResult());
        Assert.assertTrue(verify.getResult());
    }

    /**
     * case： issuer is null.
     */
    @Test
    public void testCreateCredential_issuerNull() {

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        createCredentialPojoArgs.setIssuer(null);

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUER_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： issuer is invalid.
     */
    @Test
    public void testCreateCredential_invalidIssuer() {

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        createCredentialPojoArgs.setIssuer("di:weid:0x11!@#$%^&*()_+zhon 中国》《？12qwe");

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUER_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： private key is sdk private key.
     */
    @Test
    public void testCreateCredential_sdkPriKey() {

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        WeIdAuthentication weIdAuthentication = createCredentialPojoArgs.getWeIdAuthentication();
        WeIdPrivateKey weIdPrivateKey = new WeIdPrivateKey();
        weIdPrivateKey.setPrivateKey(privateKey);
        weIdAuthentication.setWeIdPrivateKey(weIdPrivateKey);

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }


    /**
     * case: issuance date = 0,create success and verify success.
     */
    @Test
    public void createCredential_withIssuanceZero() {
        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        createCredentialPojoArgs.setIssuanceDate(0L);

        ResponseData<CredentialPojo> response = credentialPojoService
            .createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUANCE_DATE_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case:issuance date data is minus number.
     */
    @Test
    public void testCreateCredential_issuanceDateMinus() {
        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        createCredentialPojoArgs.setIssuanceDate(-1L);

        ResponseData<CredentialPojo> response = credentialPojoService
            .createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUANCE_DATE_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
    }

    /**
     * case: issuance date is a big integer.
     */
    @Test
    public void testCreateCredential_bigIssuanceDate() {

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        createCredentialPojoArgs.setIssuanceDate(Long.MAX_VALUE);

        ResponseData<CredentialPojo> response = credentialPojoService
            .createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUANCE_DATE_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
    }

    /**
     * case:issuance date is Long.MIN_VALUE
     */
    @Test
    public void testCreateCredential_minIsuanceDate() {

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs
            = TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        createCredentialPojoArgs.setIssuanceDate(Long.MIN_VALUE);

        ResponseData<CredentialPojo> response = credentialPojoService
            .createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUANCE_DATE_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： expirationDate <= 0.
     */
    @Test
    public void testCreateCredential_minusExpirationDate() {

        CreateCredentialPojoArgs createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setExpirationDate(0L);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_EXPIRE_DATE_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： expirationDate <= now.
     */
    @Test
    public void testCreateCredential_passedExpirationDate() {

        CreateCredentialPojoArgs createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setExpirationDate(System.currentTimeMillis() - 1000000);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_EXPIRED.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case:expiration date is null.
     */
    @Test
    public void testCreateCredential_expirationDateNull() {
        CreateCredentialPojoArgs createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        createCredentialPojoArgs.setExpirationDate(null);

        ResponseData<CredentialPojo> response = credentialPojoService
            .createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_EXPIRE_DATE_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： claim is null.
     */
    @Test
    public void testCreateCredential_claimNull() {

        CreateCredentialPojoArgs createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        createCredentialPojoArgs.setClaim(null);

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_CLAIM_NOT_EXISTS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： claim is xxxxxxx.
     */
    @Test
    public void testCreateCredential_invalidClaim() {

        CreateCredentialPojoArgs createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        HashMap<String, Object> claim = new HashMap<>();
        claim.put("xxxxxxxxxxxxxx", "xxxxxxxxxxxxxx");
        createCredentialPojoArgs.setClaim(claim);

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        ResponseData<Boolean> verify = credentialPojoService
            .verify(createCredentialPojoArgs.getIssuer(), response.getResult());
        Assert.assertEquals(
            ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL.getCode(), verify.getErrorCode().intValue());
        Assert.assertFalse(verify.getResult());
    }

    /**
     * case:claim is a json.
     */
    @Test
    public void testCreateCredential_jsonClaim() {

        CreateCredentialPojoArgs<Map<String, Object>> createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        Map<String, Object> claim = new HashMap<>();
        claim.put("name", 20);
        createCredentialPojoArgs.setClaim(claim);

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        ResponseData<Boolean> verify = credentialPojoService
            .verify(createCredentialPojoArgs.getIssuer(), response.getResult());
        Assert.assertEquals(
            ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL.getCode(), verify.getErrorCode().intValue());
        Assert.assertFalse(verify.getResult());
    }

    /**
     * case： weIdPrivateKey is null.
     */
    @Test
    public void testCreateCredential_priKeyNull() {

        CreateCredentialPojoArgs createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        WeIdAuthentication weIdAuthentication = new WeIdAuthentication();
        weIdAuthentication.setWeId(createWeIdResultWithSetAttr.getWeId());
        weIdAuthentication.setWeIdPublicKeyId(
            createWeIdResultWithSetAttr.getUserWeIdPublicKey().getPublicKey());
        createCredentialPojoArgs.setWeIdAuthentication(weIdAuthentication);

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： publicKey is null.
     */
    @Test
    public void testCreateCredential_pubKeyNull() {

        CreateCredentialPojoArgs createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        WeIdAuthentication weIdAuthentication = new WeIdAuthentication();
        weIdAuthentication.setWeId(createWeIdResultWithSetAttr.getWeId());
        weIdAuthentication.setWeIdPrivateKey(createWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        weIdAuthentication.setWeIdPublicKeyId(
            createWeIdResultWithSetAttr.getUserWeIdPublicKey().getPublicKey() + "56");
        createCredentialPojoArgs.setWeIdAuthentication(weIdAuthentication);

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        ResponseData<Boolean> verify = credentialPojoService
            .verify(createCredentialPojoArgs.getIssuer(), response.getResult());
        Assert.assertTrue(verify.getResult());

    }

    /**
     * case： issuer and weIdAuthentication.weId is different,createCredentialPojo fail.
     */
    @Test
    public void testCreateCredential_otherWeId() {

        CreateCredentialPojoArgs createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        WeIdAuthentication weIdAuthentication = new WeIdAuthentication();
        weIdAuthentication.setWeId(createWeIdNew.getWeId());
        weIdAuthentication.setWeIdPublicKeyId(createWeIdNew.getUserWeIdPublicKey().getPublicKey());
        weIdAuthentication.setWeIdPrivateKey(createWeIdNew.getUserWeIdPrivateKey());
        createCredentialPojoArgs.setWeIdAuthentication(weIdAuthentication);

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUER_INVALID.getCode(),
            response.getErrorCode().intValue());
    }

    /**
     * case： privateKey is issuer private key.
     */
    @Test
    public void testCreateCredential_issuerPriKey() {

        CreateCredentialPojoArgs createCredentialPojoArgs =
            TestBaseUtil.buildCreateCredentialPojoArgs(createWeIdResultWithSetAttr);
        createCredentialPojoArgs.setCptId(cptBaseInfo.getCptId());
        WeIdAuthentication weIdAuthentication = new WeIdAuthentication();
        weIdAuthentication.setWeId(createWeIdNew.getWeId());
        weIdAuthentication.setWeIdPrivateKey(createWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        createCredentialPojoArgs.setWeIdAuthentication(weIdAuthentication);

        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialPojoArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUER_INVALID.getCode(),
            response.getErrorCode().intValue());
    }

    @Test
    public void testCreateAuthTokenAll() throws Exception {

        // Enforce a Register/Update system CPT first
        WeIdAuthentication sdkAuthen = new WeIdAuthentication();
        CryptoKeyPair keyPair = DataToolUtils.createKeyPairFromPrivate(new BigInteger(privateKey));
        String keyWeId = WeIdUtils
            .convertAddressToWeId(keyPair.getAddress());
        sdkAuthen.setWeId(keyWeId);
        WeIdPrivateKey weIdPrivateKey = new WeIdPrivateKey();
        weIdPrivateKey.setPrivateKey(privateKey);
        sdkAuthen.setWeIdPrivateKey(weIdPrivateKey);
        if (!weIdService.isWeIdExist(keyWeId).getResult()) {
            CreateWeIdArgs wargs = new CreateWeIdArgs();
            wargs.setWeIdPrivateKey(weIdPrivateKey);
            BigInteger publicKey = 
                new BigInteger(1, Numeric.hexStringToByteArray(keyPair.getHexPublicKey()));
            wargs.setPublicKey(publicKey.toString(10));
            weIdService.createWeId(wargs);
        }
        String cptJsonSchema = DataToolUtils
            .generateDefaultCptJsonSchema(Class.forName("com.webank.weid.protocol.cpt.Cpt101"));
        CptStringArgs args = new CptStringArgs();
        args.setCptJsonSchema(cptJsonSchema);
        args.setWeIdAuthentication(sdkAuthen);
        if (cptService.queryCpt(CredentialConstant.AUTHORIZATION_CPT).getResult() == null) {
            cptService.registerCpt(args, CredentialConstant.AUTHORIZATION_CPT);
        } else {
            cptService.updateCpt(args, CredentialConstant.AUTHORIZATION_CPT);
        }

        // Init params
        Cpt101 authInfo = new Cpt101();
        authInfo.setFromWeId(createWeIdResultWithSetAttr.getWeId());
        String toWeId = this.createWeIdWithSetAttr().getWeId();
        authInfo.setToWeId(toWeId);
        authInfo.setDuration(360000L);
        authInfo.setResourceId(UUID.randomUUID().toString());
        authInfo.setServiceUrl("http://127.0.0.1:6011/fetch-data");
        WeIdAuthentication weIdAuthentication = new WeIdAuthentication();
        weIdAuthentication.setWeId(createWeIdResultWithSetAttr.getWeId());
        weIdAuthentication.setWeIdPrivateKey(createWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        weIdAuthentication.setWeIdPublicKeyId(createWeIdResultWithSetAttr.getWeId() + "#keys-0");

        // Create and check
        ResponseData<CredentialPojo> authTokenCredResp = credentialPojoService
            .createDataAuthToken(authInfo, weIdAuthentication);
        Assert.assertEquals(authTokenCredResp.getErrorCode().intValue(),
            ErrorCode.SUCCESS.getCode());
        CredentialPojo authToken = authTokenCredResp.getResult();
        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(authToken.getIssuer(), authToken);
        Assert.assertTrue(verifyResp.getResult());
    }
}
