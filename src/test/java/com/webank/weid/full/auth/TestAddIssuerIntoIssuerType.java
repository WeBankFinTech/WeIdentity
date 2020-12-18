package com.webank.weid.full.auth;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.full.TestBaseService;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.request.RemoveAuthorityIssuerArgs;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;

public class TestAddIssuerIntoIssuerType extends TestBaseService {

    private static final Logger logger = LoggerFactory.getLogger(TestAddIssuerIntoIssuerType.class);

    private static CreateWeIdDataResult createWeId;

    private String issuerType = null;

    @Override
    public synchronized void testInit() {

        super.testInit();
        if (createWeId == null) {
            createWeId = super.registerAuthorityIssuer();
        }
        if (issuerType == null) {
            issuerType = super.registerIssuerType("college");
        }
    }

    /**
     * case : test repeat add issuer into issuer type success.
     */
    @Test
    public void testAddIssuerIntoIssuerType_repeatFail() {
        WeIdAuthentication weIdAuthentication =
            TestBaseUtil.buildWeIdAuthentication(createWeId);
        weIdAuthentication.setWeIdPrivateKey(privateKey);
        CreateWeIdDataResult weId = super.createWeId();

        ResponseData<Boolean> response = authorityIssuerService
            .addIssuerIntoIssuerType(weIdAuthentication, issuerType, weId.getWeId());
        LogUtil.info(logger, "addIssuerIntoIssuerType", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertTrue(response.getResult());

        ResponseData<Boolean> res = authorityIssuerService
            .addIssuerIntoIssuerType(weIdAuthentication, issuerType, weId.getWeId());
        LogUtil.info(logger, "addIssuerIntoIssuerType", res);

        Assert.assertEquals(ErrorCode.SPECIFIC_ISSUER_CONTRACT_ERROR_ALREADY_EXISTS.getCode(),
            res.getErrorCode().intValue());
        Assert.assertFalse(res.getResult());
    }

    /**
     * caller is not authority issuer .
     */
    @Test
    public void testAddIssuerIntoIssuerType_noAuthorityIssuer() {
        WeIdAuthentication weIdAuthentication =
            TestBaseUtil.buildWeIdAuthentication(super.createWeId());

        ResponseData<Boolean> response = authorityIssuerService
            .addIssuerIntoIssuerType(weIdAuthentication, issuerType, createWeIdResult.getWeId());
        LogUtil.info(logger, "addIssuerIntoIssuerType", response);

        Assert.assertEquals(ErrorCode.CONTRACT_ERROR_NO_PERMISSION.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());
    }

    /**
     * case：caller has been remove register authority issuer,then call the api.
     */
    @Test
    public void testAddIssuerIntoIssuerType_removeAuthorityIssuer() {
        CreateWeIdDataResult weId = super.registerAuthorityIssuer();
        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs
            = TestBaseUtil.buildRemoveAuthorityIssuerArgs(weId, privateKey);
        ResponseData<Boolean> res
            = authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), res.getErrorCode().intValue());

        WeIdAuthentication weIdAuthentication =
            TestBaseUtil.buildWeIdAuthentication(weId);

        ResponseData<Boolean> response = authorityIssuerService
            .addIssuerIntoIssuerType(weIdAuthentication, issuerType, createWeIdResult.getWeId());
        LogUtil.info(logger, "addIssuerIntoIssuerType", response);

        Assert.assertEquals(ErrorCode.CONTRACT_ERROR_NO_PERMISSION.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());
    }

    /**
     * case : weId Authentication is null.
     */
    @Test
    public void testAddIssuerIntoIssuerType_callerNull() {
        WeIdAuthentication weIdAuthentication = new WeIdAuthentication();

        ResponseData<Boolean> response = authorityIssuerService
            .addIssuerIntoIssuerType(weIdAuthentication, issuerType, createWeIdResult.getWeId());
        LogUtil.info(logger, "addIssuerIntoIssuerType", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());
    }

    /**
     * case: caller is blank.
     */
    @Test
    public void testAddIssuerIntoIssuerType_callerBlank() {
        WeIdAuthentication weIdAuthentication = TestBaseUtil.buildWeIdAuthentication(createWeId);
        weIdAuthentication.setWeId("");

        ResponseData<Boolean> response = authorityIssuerService
            .addIssuerIntoIssuerType(weIdAuthentication, issuerType, createWeIdResult.getWeId());
        LogUtil.info(logger, "addIssuerIntoIssuerType", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());
    }

    /**
     * case: caller is blank.
     */
    @Test
    public void testAddIssuerIntoIssuerType_invalidCaller() {
        WeIdAuthentication weIdAuthentication = TestBaseUtil.buildWeIdAuthentication(createWeId);
        weIdAuthentication.setWeId("！@#￥%……&*（）：，。");

        ResponseData<Boolean> response = authorityIssuerService
            .addIssuerIntoIssuerType(weIdAuthentication, issuerType, createWeIdResult.getWeId());
        LogUtil.info(logger, "addIssuerIntoIssuerType", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());
    }

    /**
     * case: private key is null.
     */
    @Test
    public void testAddIssuerIntoIssuerType_privateKeyNull() {
        WeIdAuthentication weIdAuthentication = TestBaseUtil.buildWeIdAuthentication(createWeId);
        weIdAuthentication.setWeIdPrivateKey(null);

        ResponseData<Boolean> response = authorityIssuerService
            .addIssuerIntoIssuerType(weIdAuthentication, issuerType, createWeIdResult.getWeId());
        LogUtil.info(logger, "addIssuerIntoIssuerType", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());
    }

    /**
     * case: private key is blank.
     */
    @Test
    public void testAddIssuerIntoIssuerType_privateKeyBlank() {
        WeIdAuthentication weIdAuthentication = TestBaseUtil.buildWeIdAuthentication(createWeId);
        WeIdPrivateKey weIdPrivateKey = new WeIdPrivateKey();
        weIdPrivateKey.setPrivateKey("");
        weIdAuthentication.setWeIdPrivateKey(weIdPrivateKey);

        ResponseData<Boolean> response = authorityIssuerService
            .addIssuerIntoIssuerType(weIdAuthentication, issuerType, createWeIdResult.getWeId());
        LogUtil.info(logger, "addIssuerIntoIssuerType", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());
    }

    /**
     * case: private key is belong other weId.
     */
    @Test
    public void testAddIssuerIntoIssuerType_otherPriKey() {
        WeIdAuthentication weIdAuthentication = TestBaseUtil.buildWeIdAuthentication(createWeId);
        weIdAuthentication.setWeIdPrivateKey(createWeIdResult.getUserWeIdPrivateKey());

        ResponseData<Boolean> response = authorityIssuerService
            .addIssuerIntoIssuerType(weIdAuthentication, issuerType, createWeIdResult.getWeId());
        LogUtil.info(logger, "addIssuerIntoIssuerType", response);

        Assert.assertEquals(ErrorCode.CONTRACT_ERROR_NO_PERMISSION.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());
    }

    /**
     * case: private key is belong other weId.
     */
    @Test
    public void testAddIssuerIntoIssuerType_otherAuthorPriKey() {
        WeIdAuthentication weIdAuthentication = TestBaseUtil.buildWeIdAuthentication(createWeId);
        CreateWeIdDataResult weIdDataResult = super.registerAuthorityIssuer();
        authorityIssuerService
            .recognizeAuthorityIssuer(weIdDataResult.getWeId(), privateKey);
        weIdAuthentication.setWeIdPrivateKey(weIdDataResult.getUserWeIdPrivateKey());

        ResponseData<Boolean> response = authorityIssuerService
            .addIssuerIntoIssuerType(weIdAuthentication, issuerType, createWeIdResult.getWeId());
        LogUtil.info(logger, "addIssuerIntoIssuerType", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertTrue(response.getResult());
    }

    /**
     * case: public key is null.
     */
    @Test
    public void testAddIssuerIntoIssuerType_PubKeyNull() {

        WeIdAuthentication weIdAuthentication = TestBaseUtil.buildWeIdAuthentication(createWeId);
        weIdAuthentication.setWeIdPrivateKey(privateKey);
        weIdAuthentication.setWeIdPublicKeyId(null);

        ResponseData<Boolean> response = authorityIssuerService
            .addIssuerIntoIssuerType(weIdAuthentication, issuerType, super.createWeId().getWeId());
        LogUtil.info(logger, "addIssuerIntoIssuerType", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertTrue(response.getResult());
    }

    /**
     * case: public key contain any special char.
     */
    @Test
    public void testAddIssuerIntoIssuerType_PubKeyContainChar() {
        WeIdAuthentication weIdAuthentication = TestBaseUtil.buildWeIdAuthentication(createWeId);
        char[] chars = new char[100];
        for (int i = 0; i < chars.length; i++) {
            chars[i] = (char) (i % 127);
        }
        weIdAuthentication.setWeIdPublicKeyId(String.valueOf(chars));
        weIdAuthentication.setWeIdPrivateKey(privateKey);

        ResponseData<Boolean> response = authorityIssuerService
            .addIssuerIntoIssuerType(weIdAuthentication, issuerType, super.createWeId().getWeId());
        LogUtil.info(logger, "addIssuerIntoIssuerType", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertTrue(response.getResult());
    }

    /**
     * case: issuer is not exist on chain.
     */
    @Test
    public void testAddIssuerIntoIssuerType_issuerNotExist() {
        WeIdAuthentication weIdAuthentication = TestBaseUtil.buildWeIdAuthentication(createWeId);

        ResponseData<Boolean> response = authorityIssuerService
            .addIssuerIntoIssuerType(weIdAuthentication, issuerType,
                "did:weid:0xc7e399b8d2da337f4e92eb33ca88b60b899ff022");
        LogUtil.info(logger, "addIssuerIntoIssuerType", response);

        Assert.assertEquals(ErrorCode.WEID_DOES_NOT_EXIST.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());
    }


    /**
     * case: invalid issuer.
     */
    @Test
    public void testAddIssuerIntoIssuerType_invalidIssuer() {
        WeIdAuthentication weIdAuthentication = TestBaseUtil.buildWeIdAuthentication(createWeId);

        ResponseData<Boolean> response = authorityIssuerService
            .addIssuerIntoIssuerType(weIdAuthentication, issuerType,
                "did:weid:0xc7e399b8d2da337f4e92eb33ca88b60b899");
        LogUtil.info(logger, "addIssuerIntoIssuerType", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());
    }

}
