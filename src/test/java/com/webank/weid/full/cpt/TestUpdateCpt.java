/*
 *       Copyright© (2018) WeBank Co., Ltd.
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

package com.webank.weid.full.cpt;

import java.io.IOException;
import java.util.HashMap;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.common.PasswordKey;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.JsonSchemaConstant;
import com.webank.weid.full.TestBaseService;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.Cpt;
import com.webank.weid.protocol.base.CptBaseInfo;
import com.webank.weid.protocol.request.CptMapArgs;
import com.webank.weid.protocol.request.CptStringArgs;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.util.WeIdUtils;

/**
 * updateCpt method for testing CptService.
 *
 * @author v_wbgyang/rockyxia
 */
public class TestUpdateCpt extends TestBaseService {

    private static final Logger logger = LoggerFactory.getLogger(TestUpdateCpt.class);

    @Override
    public synchronized void testInit() {

        super.testInit();
        if (cptBaseInfo == null) {
            cptBaseInfo = super.registerCpt(createWeIdResultWithSetAttr);
            Assert.assertTrue(cptBaseInfo.getCptId() > 2000000);
        }
    }

    /**
     * case： cpt updateCpt success, used no auth issuer to update no auth cpt.
     */
    @Test
    public void testUpdateCpt_success() {

        CreateWeIdDataResult createWeId = super.createWeIdWithSetAttr();

        CptBaseInfo cptBaseInfo = super.registerCpt(createWeId);

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptMapArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * case： cpt updateCpt success, used auth issuer to update no auth cpt.
     */
    @Test
    public void testUpdateCpt_AuthIssuerUpdateSuccess() {

        CreateWeIdDataResult createWeId = super.createWeIdWithSetAttr();

        CptBaseInfo cptBaseInfo = super.registerCpt(createWeId);

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptMapArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * case： used no auth issuer to update no auth cpt.
     */
    @Test
    public void testUpdateCpt_updateJsonSchema() throws IOException {

        CreateWeIdDataResult createWeId = super.createWeIdWithSetAttr();

        CptBaseInfo cptBaseInfo = super.registerCpt(createWeId);

        CptStringArgs cptMapStringArgs
            = TestBaseUtil.buildCptStringArgs(createWeId, false);
        cptMapStringArgs.setCptJsonSchema("{\"student\":{\"name\":\"rocky\",\"age\":20}}");

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptMapStringArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());

        ResponseData<Cpt> res = cptService.queryCpt(cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", res.getResult().toString());

        Assert.assertNotNull(res.getResult().getCptJsonSchema().get("student"));

        //update again
        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        ResponseData<CptBaseInfo> response2 = cptService.updateCpt(
            cptMapArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response2);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response2.getErrorCode().intValue());
        Assert.assertNotNull(response2.getResult());

        ResponseData<Cpt> res2 = cptService.queryCpt(cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", res2.getResult().toString());

        Assert.assertNull(res2.getResult().getCptJsonSchema().get("student"));

    }

    /**
     * case：used auth issuer to update no auth cpt.
     */
    @Test
    public void testUpdateCpt_noAuthIssuerUpdateAuthCptFail() {

        CreateWeIdDataResult createWeId = super.registerAuthorityIssuer();
        authorityIssuerService.recognizeAuthorityIssuer(createWeId.getWeId(), privateKey);
        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        CptBaseInfo cptBaseInfo = cptService.registerCpt(cptMapArgs).getResult();
        Assert.assertTrue(cptBaseInfo.getCptId() < 2000000);

        CreateWeIdDataResult createWeIdNew = super.createWeId();
        CptMapArgs cptMapArgs1 = TestBaseUtil.buildCptArgs(createWeIdNew);

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptMapArgs1,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.CPT_NO_PERMISSION.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： updateCptArgs is null.
     */
    @Test
    public void testUpdateCpt_cptMapAgsNull() {

        CptMapArgs cptMapArgs = null;
        ResponseData<CptBaseInfo> response = cptService.updateCpt(cptMapArgs, 500000);
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptId is null.
     */
    @Test
    public void testUpdateCpt_cptIdNull() {

        CptMapArgs cptMapArgs =
            TestBaseUtil.buildCptArgs(createWeIdResultWithSetAttr);

        ResponseData<CptBaseInfo> response = cptService.updateCpt(cptMapArgs, null);
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.CPT_ID_ILLEGAL.getCode(), 
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptId is minus number.
     */
    @Test
    public void testUpdateCpt_minusCptId() {

        CptMapArgs cptMapArgs =
            TestBaseUtil.buildCptArgs(createWeIdResultWithSetAttr);

        ResponseData<CptBaseInfo> response = cptService.updateCpt(cptMapArgs, -1);
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.CPT_ID_ILLEGAL.getCode(), 
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptId is not exists.
     */
    @Test
    public void testUpdateCpt_cptIdNotExist() {

        CptMapArgs cptMapArgs =
            TestBaseUtil.buildCptArgs(createWeIdResultWithSetAttr);

        ResponseData<CptBaseInfo> response = cptService.updateCpt(cptMapArgs, 999999999);
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(
            ErrorCode.CPT_NO_PERMISSION.getCode(),
            response.getErrorCode().intValue()
        );
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptJsonSchema is null.
     */
    @Test
    public void testUpdateCpt_cptJsonSchemaNull() {

        CptMapArgs cptMapArgs =
            TestBaseUtil.buildCptArgs(createWeIdResultWithSetAttr);
        cptMapArgs.setCptJsonSchema(null);

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptMapArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.CPT_JSON_SCHEMA_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptJsonSchema too long.
     */
    @Test
    public void testUpdateCpt_cptJsonSchemaTooLong() throws JsonProcessingException, IOException {

        CptMapArgs cptMapArgs =
            TestBaseUtil.buildCptArgs(createWeIdResultWithSetAttr);

        StringBuffer value = new StringBuffer("");
        for (int i = 0; i < 5000; i++) {
            value.append("x");
        }

        HashMap<String, Object> cptJsonSchema = TestBaseUtil.buildCptJsonSchema();
        cptJsonSchema.put(JsonSchemaConstant.TITLE_KEY, value.toString());
        cptMapArgs.setCptJsonSchema(cptJsonSchema);

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptMapArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.CPT_JSON_SCHEMA_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptPublisher is blank.
     */
    @Test
    public void testUpdateCpt_cptPublisherBlank() {

        CptMapArgs cptMapArgs =
            TestBaseUtil.buildCptArgs(createWeIdResultWithSetAttr);
        cptMapArgs.getWeIdAuthentication().setWeId(null);

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptMapArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptPublisher is invalid.
     */
    @Test
    public void testUpdateCpt_invalidCptPublisher() {

        CptMapArgs cptMapArgs =
            TestBaseUtil.buildCptArgs(createWeIdResultWithSetAttr);
        cptMapArgs.getWeIdAuthentication().setWeId("di:weid:0xaaaaaaaaaaaaaaaa");

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptMapArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptPublisher is not exists and the private key does not match.
     */
    @Test
    public void testUpdateCpt_cptPublisherNotExist() {

        CptMapArgs cptMapArgs =
            TestBaseUtil.buildCptArgs(createWeIdResultWithSetAttr);
        cptMapArgs.getWeIdAuthentication()
            .setWeId("did:weid:0xbb1670306aedfaeb75cff9581c99e56ba4797431");

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptMapArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());

        ResponseData<Cpt> responseCpt = cptService.queryCpt(cptBaseInfo.getCptId());
        LogUtil.info(logger, "queryCpt", responseCpt);
    }

    /**
     * case： cptPublisherPrivateKey is null.
     */
    @Test
    public void testUpdateCptCase_priKeyNull() {

        CptMapArgs cptMapArgs =
            TestBaseUtil.buildCptArgs(createWeIdResultWithSetAttr);
        cptMapArgs.getWeIdAuthentication().setWeIdPrivateKey(null);

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptMapArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： private Key is null.
     */
    @Test
    public void testUpdateCptCase13() {

        CptMapArgs cptMapArgs =
            TestBaseUtil.buildCptArgs(createWeIdResultWithSetAttr);
        cptMapArgs.getWeIdAuthentication().getWeIdPrivateKey().setPrivateKey(null);

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptMapArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： privateKey is invalid.
     */
    @Test
    public void testUpdateCptCase14() {

        CptMapArgs cptMapArgs =
            TestBaseUtil.buildCptArgs(createWeIdResultWithSetAttr);
        cptMapArgs.getWeIdAuthentication().getWeIdPrivateKey().setPrivateKey("123132545646878901");

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptMapArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： privateKey is new privateKey.
     */
    @Test
    public void testUpdateCptCase15() {

        CptMapArgs cptMapArgs =
            TestBaseUtil.buildCptArgs(createWeIdResultWithSetAttr);
        cptMapArgs.getWeIdAuthentication()
            .setWeIdPrivateKey(TestBaseUtil.createEcKeyPair().getPrivateKey());

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptMapArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： privateKey belongs to SDK.
     */
    @Test
    public void testUpdateCptCase16() {

        CptMapArgs cptMapArgs =
            TestBaseUtil.buildCptArgs(createWeIdResultWithSetAttr);
        cptMapArgs.getWeIdAuthentication().setWeIdPrivateKey(privateKey);

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptMapArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： privateKey belongs to new WeIdentity DID.
     */
    @Test
    public void testUpdateCptCase17() {

        CptMapArgs cptMapArgs =
            TestBaseUtil.buildCptArgs(createWeIdResultWithSetAttr);
        cptMapArgs.getWeIdAuthentication().setWeIdPrivateKey(createWeIdNew.getUserWeIdPrivateKey());

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptMapArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： privateKey belongs to new WeIdentity DID , cptPublisher is a new WeId. [TIP] update
     * success,we will deal with the two issue.
     */
    @Test
    public void testUpdateCpt_updatePublisher() {

        CptMapArgs cptMapArgs =
            TestBaseUtil.buildCptArgs(createWeIdResult);
        cptMapArgs.getWeIdAuthentication().setWeId(createWeIdNew.getWeId());
        cptMapArgs.getWeIdAuthentication().setWeIdPrivateKey(createWeIdNew.getUserWeIdPrivateKey());

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptMapArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(
            ErrorCode.CPT_NO_PERMISSION.getCode(),
            response.getErrorCode().intValue()
        );
    }

    /**
     * case： privateKey is xxxxxxx.
     */
    @Test
    public void testUpdateCptCase19() {

        CptMapArgs cptMapArgs =
            TestBaseUtil.buildCptArgs(createWeIdResultWithSetAttr);
        cptMapArgs.getWeIdAuthentication().getWeIdPrivateKey().setPrivateKey("xxxxxxxxxx");

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptMapArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptPublisher is not exists , but private key matching.
     */
    @Test
    public void testUpdateCptCase20() {

        PasswordKey passwordKey = TestBaseUtil.createEcKeyPair();
        String weId = WeIdUtils.convertPublicKeyToWeId(passwordKey.getPublicKey());

        CptMapArgs cptMapArgs =
            TestBaseUtil.buildCptArgs(createWeIdResultWithSetAttr);
        cptMapArgs.getWeIdAuthentication().setWeId(weId);
        cptMapArgs.getWeIdAuthentication()
            .setWeIdPrivateKey(passwordKey.getPrivateKey());

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptMapArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.CPT_PUBLISHER_NOT_EXIST.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());

        ResponseData<Cpt> responseCpt = cptService.queryCpt(cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", responseCpt);
    }

    /**
     * case： build cpt string.
     */
    @Test
    public void testUpdateCptCase23() throws IOException {

        CreateWeIdDataResult createWeId = super.createWeIdWithSetAttr();

        CptBaseInfo cptBaseInfo = super.registerCpt(createWeId);

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, false);

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptStringArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * case： build cpt string, args is null.
     */
    @Test
    public void testUpdateCptCase24() {

        CptStringArgs cptStringArgs = null;

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptStringArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： build cpt string for unkonw_error.
     */
    @Test
    public void testUpdateCptCase25() throws IOException {

        CreateWeIdDataResult createWeId = super.createWeIdWithSetAttr();

        CptBaseInfo cptBaseInfo = super.registerCpt(createWeId);

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, false);
        cptStringArgs.setCptJsonSchema("xxxx");

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptStringArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(
            ErrorCode.UNKNOW_ERROR.getCode(),
            response.getErrorCode().intValue()
        );
        Assert.assertNull(response.getResult());
    }

    /**
     * case： build cpt string by file.
     */
    @Test
    public void testUpdateCptCase26() throws IOException {

        CreateWeIdDataResult createWeId = super.createWeIdWithSetAttr();

        CptBaseInfo cptBaseInfo = super.registerCpt(createWeId);

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, true);

        ResponseData<CptBaseInfo> response = cptService.updateCpt(
            cptStringArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

}
