package com.webank.weid.full.auth;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.full.TestBaseService;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;

public class TestRemoveIssuerFromIssuerType extends TestBaseService {

    private static final Logger logger = LoggerFactory
        .getLogger(TestRemoveIssuerFromIssuerType.class);

    private static CreateWeIdDataResult createWeId;

    private static CreateWeIdDataResult createWeIdData;

    private String issuerType = null;

    private static CreateWeIdDataResult issuer;

    private static WeIdAuthentication callerAuth = new WeIdAuthentication();

    @Override
    public synchronized void testInit() {

        super.testInit();
        if (createWeId == null) {
            createWeId = super.registerAuthorityIssuer();
        }
        if (createWeIdData == null) {
            createWeIdData = super.createWeId();
        }
        if (issuerType == null) {
            issuerType = super.registerIssuerType("rockyXia");
        }
    }

    /**
     * add issuer into issuer type.
     */
    @Before
    public void andIssuerIntoIssuerType() {
        callerAuth.setWeId(createWeId.getWeId());
        callerAuth.setWeIdPublicKeyId(createWeId.getUserWeIdPublicKey().getPublicKey());
        callerAuth.setWeIdPrivateKey(createWeId.getUserWeIdPrivateKey());
        authorityIssuerService.recognizeAuthorityIssuer(createWeId.getWeId(), privateKey);

        issuer = super.createWeId();
        ResponseData<Boolean> response = authorityIssuerService
            .addIssuerIntoIssuerType(callerAuth, issuerType, issuer.getWeId());
        LogUtil.info(logger, "addIssuerIntoIssuerType", response);
    }

    /**
     * remove issuer from issuer type.
     */
    @After
    public void removeIssuerFromIssuerType() {
        callerAuth.setWeId(createWeId.getWeId());
        callerAuth.setWeIdPublicKeyId(createWeId.getUserWeIdPublicKey().getPublicKey());
        callerAuth.setWeIdPrivateKey(createWeId.getUserWeIdPrivateKey());

        ResponseData<Boolean> res = authorityIssuerService
            .removeIssuerFromIssuerType(callerAuth, issuerType, issuer.getWeId());
        LogUtil.info(logger, "removeIssuerFromIssuerType", res);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), res.getErrorCode().intValue());
    }

    /**
     * case:callerAuth is not authorityIssuer .
     */
    @Test
    public void testRemoveIssuerFromIssuerType_notAuthIssuer() {
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(createWeIdData);

        ResponseData<Boolean> response = authorityIssuerService.removeIssuerFromIssuerType(
            callerAuth, issuerType, issuer.getWeId());
        LogUtil.info(logger, "removeIssuerFromIssuerType", response);

        Assert.assertEquals(ErrorCode.CONTRACT_ERROR_NO_PERMISSION.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());
    }

    /**
     * case:callerAuth weId not match private key.
     */
    @Test
    public void testRemoveIssuerFromIssuerType_callerAuthPriKeyNotMatch() {
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(createWeId);
        final WeIdPrivateKey key = createWeId.getUserWeIdPrivateKey();
        callerAuth.setWeIdPrivateKey(createWeIdData.getUserWeIdPrivateKey());

        ResponseData<Boolean> response = authorityIssuerService.removeIssuerFromIssuerType(
            callerAuth, issuerType, issuer.getWeId());
        LogUtil.info(logger, "removeIssuerFromIssuerType", response);

        callerAuth.setWeIdPrivateKey(key);
        Assert.assertEquals(ErrorCode.CONTRACT_ERROR_NO_PERMISSION.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());
    }

    /**
     * case:callerAuth is null.
     */
    @Test
    public void testRemoveIssuerFromIssuerType_callerAuthPriKeyNull() {

        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(createWeId);
        final WeIdPrivateKey key = createWeId.getUserWeIdPrivateKey();
        callerAuth.setWeIdPrivateKey(null);

        ResponseData<Boolean> response = authorityIssuerService.removeIssuerFromIssuerType(
            callerAuth, issuerType, issuer.getWeId());
        LogUtil.info(logger, "removeIssuerFromIssuerType", response);

        callerAuth.setWeIdPrivateKey(key);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());
    }

    /**
     * case:callerAuth is null.
     */
    @Test
    public void testRemoveIssuerFromIssuerType_callerAuthNull() {
        WeIdAuthentication callerAuth = new WeIdAuthentication();

        ResponseData<Boolean> response = authorityIssuerService.removeIssuerFromIssuerType(
            callerAuth, issuerType, issuer.getWeId());
        LogUtil.info(logger, "removeIssuerFromIssuerType", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());
    }

    /**
     * case:issuer type not exist.
     */
    @Test
    public void testRemoveIssuerFromIssuerType_issuerTypeNotRegister() {

        ResponseData<Boolean> response = authorityIssuerService.removeIssuerFromIssuerType(
            callerAuth, "中国人民-chinese people", issuer.getWeId());
        LogUtil.info(logger, "removeIssuerFromIssuerType", response);

        Assert.assertEquals(ErrorCode.SPECIFIC_ISSUER_CONTRACT_ERROR_ALREADY_NOT_EXIST.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());

    }

    /**
     * case:issuer type is null.
     */
    @Test
    public void testRemoveIssuerFromIssuerType_issuerTypeNull() {

        ResponseData<Boolean> response = authorityIssuerService.removeIssuerFromIssuerType(
            callerAuth, null, issuer.getWeId());
        LogUtil.info(logger, "removeIssuerFromIssuerType", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());

    }

    /**
     * case:issuer type is blank.
     */
    @Test
    public void testRemoveIssuerFromIssuerType_issuerTypeBlank() {

        ResponseData<Boolean> response = authorityIssuerService.removeIssuerFromIssuerType(
            callerAuth, null, issuer.getWeId());
        LogUtil.info(logger, "removeIssuerFromIssuerType", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());
    }

    /**
     * case:issuer is not in issuer type.
     */
    @Test
    public void testRemoveIssuerFromIssuerType_issuerNotInIssuerType() {

        ResponseData<Boolean> response = authorityIssuerService.removeIssuerFromIssuerType(
            callerAuth, issuerType, createWeIdData.getWeId());
        LogUtil.info(logger, "removeIssuerFromIssuerType", response);

        Assert.assertEquals(ErrorCode.SPECIFIC_ISSUER_CONTRACT_ERROR_ALREADY_NOT_EXIST.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());
    }

    /**
     * case:issuer is not in issuer type.
     */
    @Test
    public void testRemoveIssuerFromIssuerType_issuerNull() {

        ResponseData<Boolean> response = authorityIssuerService.removeIssuerFromIssuerType(
            callerAuth, issuerType, null);
        LogUtil.info(logger, "removeIssuerFromIssuerType", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());
    }

    /**
     * case:invalid issuer.
     */
    @Test
    public void testRemoveIssuerFromIssuerType_invalidIssuer() {

        ResponseData<Boolean> response = authorityIssuerService.removeIssuerFromIssuerType(
            callerAuth, issuerType, "ni!@#$%^&*()-+");
        LogUtil.info(logger, "removeIssuerFromIssuerType", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(response.getResult());
    }
}
