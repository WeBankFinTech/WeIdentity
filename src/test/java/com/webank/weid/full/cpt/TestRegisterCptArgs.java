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

package com.webank.weid.full.cpt;

import java.io.IOException;
import java.util.HashMap;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.lang3.StringUtils;
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
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.request.CptMapArgs;
import com.webank.weid.protocol.request.CptStringArgs;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.rpc.RawTransactionService;
import com.webank.weid.service.impl.RawTransactionServiceImpl;
import com.webank.weid.util.WeIdUtils;

/**
 * registerCpt(CptMapArgs args) method for testing CptService.
 *
 * @author v_wbgyang.
 */
public class TestRegisterCptArgs extends TestBaseService {

    private static final Logger logger = LoggerFactory.getLogger(TestRegisterCptArgs.class);

    private static CreateWeIdDataResult createWeId = null;

    @Override
    public synchronized void testInit() {

        super.testInit();
        if (createWeId == null) {
            createWeId = super.createWeId();
            super.registerAuthorityIssuer(createWeId);
            authorityIssuerService
                .recognizeAuthorityIssuer(createWeId.getWeId(), privateKey);
        }
    }

    /**
     * case： cpt register success and query sucess.
     */
    @Test
    public void testRegisterCpt_success() {

        CptMapArgs registerCptArgs = TestBaseUtil.buildCptArgs(createWeId);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(registerCptArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        CptBaseInfo cptBaseInfo = response.getResult();
        Assert.assertTrue(cptBaseInfo.getCptId().intValue() > 1000);
        Assert.assertTrue(cptBaseInfo.getCptId().intValue() < 300000);

        Integer cptId = cptBaseInfo.getCptId();
        ResponseData<Cpt> reponse = cptService.queryCpt(cptId);
        Assert.assertNotNull(reponse.getResult());
    }

    /**
     * case： weId who has not register auth issuer register cpt  success and query sucess.
     */
    @Test
    public void testRegisterCpt_weIdNotAuthIssuer() {

        ResponseData<Boolean> isAuthIssuer = authorityIssuerService
            .isAuthorityIssuer(createWeIdNew.getWeId());
        Assert.assertFalse(isAuthIssuer.getResult());

        CptMapArgs registerCptArgs = TestBaseUtil.buildCptArgs(createWeIdNew);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(registerCptArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        CptBaseInfo cptBaseInfo = response.getResult();
        Assert.assertTrue(cptBaseInfo.getCptId().intValue() > 2000000);
    }

    /**
     * case： cpt register success and query sucess.
     */
    @Test
    public void testRegisterCpt_buildDemoSuccess() {

        HashMap<String, Object> cptJsonSchema = new HashMap<String, Object>(3);
        cptJsonSchema.put("标题", "cpt template");
        cptJsonSchema.put("描述", "this is a cpt template");

        HashMap<String, Object> propertitesMap1 = new HashMap<String, Object>(2);
        propertitesMap1.put(JsonSchemaConstant.TYPE_KEY, JsonSchemaConstant.DATA_TYPE_STRING);
        propertitesMap1.put("描述", "this is name");

        String[] genderEnum = {"女性", "男性"};
        HashMap<String, Object> propertitesMap2 = new HashMap<String, Object>(2);
        propertitesMap2.put(JsonSchemaConstant.TYPE_KEY, JsonSchemaConstant.DATA_TYPE_STRING);
        propertitesMap2.put(JsonSchemaConstant.DATA_TYPE_ENUM, genderEnum);

        HashMap<String, Object> propertitesMap3 = new HashMap<String, Object>(2);
        propertitesMap3.put(JsonSchemaConstant.TYPE_KEY, JsonSchemaConstant.DATA_TYPE_NUMBER);
        propertitesMap3.put("描述", "this is age");

        HashMap<String, Object> cptJsonSchemaKeys = new HashMap<String, Object>(3);
        cptJsonSchemaKeys.put("name", propertitesMap1);
        cptJsonSchemaKeys.put("gender", propertitesMap2);
        cptJsonSchemaKeys.put("age", propertitesMap3);
        cptJsonSchema.put(JsonSchemaConstant.PROPERTIES_KEY, cptJsonSchemaKeys);

        String[] genderRequired = {"name", "gender"};
        cptJsonSchema.put(JsonSchemaConstant.REQUIRED_KEY, genderRequired);

        WeIdAuthentication weIdAuthentication = new WeIdAuthentication();
        weIdAuthentication.setWeId(createWeId.getWeId());
        weIdAuthentication.setWeIdPrivateKey(createWeId.getUserWeIdPrivateKey());

        CptMapArgs cptMapArgs = new CptMapArgs();
        cptMapArgs.setCptJsonSchema(cptJsonSchema);
        cptMapArgs.setWeIdAuthentication(weIdAuthentication);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(registerCptArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        CptBaseInfo cptBaseInfo = response.getResult();
        Assert.assertTrue(cptBaseInfo.getCptId().intValue() > 1000);
        Assert.assertTrue(cptBaseInfo.getCptId().intValue() < 3000000);
    }

    /**
     * case： cptPublisher is not exists and the private key does not match.
     */
    @Test
    public void testRegisterCpt_weIdNotExist() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication()
            .setWeId("did:weid:0xbb1670306aedfaeb75cff9581c99e56ba4797431");

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： registerCptArgs is null.
     */
    @Test
    public void testRegisterCpt_CptArgsNull() {

        CptMapArgs cptMapArgs = null;
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptJsonSchema is null.
     */
    @Test
    public void testRegisterCpt_cptJsonSchemaNull() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.setCptJsonSchema(null);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.CPT_JSON_SCHEMA_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptJsonSchema is null.
     */
    @Test
    public void testRegisterCpt_cptJsonSchemaMapNull() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.setCptJsonSchema(new HashMap<>());

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.CPT_JSON_SCHEMA_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptJsonSchema is a map.
     */
    @Test
    public void testRegisterCpt_cptJsonSchema() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        HashMap<String, Object> cptJsonSchema = new HashMap<>();
        cptMapArgs.setCptJsonSchema(cptJsonSchema);
        cptJsonSchema.put("name", "rocky xia is good man");
        cptJsonSchema.put("年龄", 18);
        cptJsonSchema.put("account", 192.5);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());

        Integer cptId = response.getResult().getCptId();
        ResponseData<Cpt> res = cptService.queryCpt(cptId);
        LogUtil.info(logger, "queryCpt", response);

        Assert.assertEquals(18, res.getResult().getCptJsonSchema().get("年龄"));
    }

    /**
     * case： cptJsonSchema nest cptJsonSchema.
     */
    @Test
    public void testRegisterCpt_cptJsonSchemaNestAndSerial() {

        HashMap<String, Object> cptJsonSchema = new HashMap<String, Object>();
        cptJsonSchema.put("标题", "cpt template");
        cptJsonSchema.put("描述", "this is a cpt template");

        HashMap<String, Object> propertitesMap1 = new HashMap<String, Object>();
        propertitesMap1.put(JsonSchemaConstant.TYPE_KEY, JsonSchemaConstant.DATA_TYPE_STRING);
        propertitesMap1.put("描述", "this is name");

        String[] genderEnum = {"女性", "男性"};
        HashMap<String, Object> propertitesMap2 = new HashMap<String, Object>();
        propertitesMap2.put(JsonSchemaConstant.TYPE_KEY, JsonSchemaConstant.DATA_TYPE_STRING);
        propertitesMap2.put(JsonSchemaConstant.DATA_TYPE_ENUM, genderEnum);

        HashMap<String, Object> propertitesMap3 = new HashMap<String, Object>(2);
        propertitesMap3.put(JsonSchemaConstant.TYPE_KEY, JsonSchemaConstant.DATA_TYPE_NUMBER);
        propertitesMap3.put("描述", "this is age");
        propertitesMap3.put("description", propertitesMap2);

        HashMap<String, Object> cptJsonSchemaKeys = new HashMap<String, Object>(3);
        cptJsonSchemaKeys.put("name", propertitesMap1);
        cptJsonSchemaKeys.put("gender", propertitesMap2);
        cptJsonSchemaKeys.put("age", propertitesMap3);
        cptJsonSchema.put(JsonSchemaConstant.PROPERTIES_KEY, cptJsonSchemaKeys);

        String[] genderRequired = {"name", "gender"};
        cptJsonSchema.put(JsonSchemaConstant.REQUIRED_KEY, genderRequired);

        WeIdAuthentication weIdAuthentication = new WeIdAuthentication();
        weIdAuthentication.setWeId(createWeId.getWeId());
        weIdAuthentication.setWeIdPrivateKey(createWeId.getUserWeIdPrivateKey());

        CptMapArgs cptMapArgs = new CptMapArgs();
        cptMapArgs.setCptJsonSchema(cptJsonSchema);
        cptMapArgs.setWeIdAuthentication(weIdAuthentication);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(registerCptArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        CptBaseInfo cptBaseInfo = response.getResult();
        Assert.assertTrue(cptBaseInfo.getCptId().intValue() > 1000);
        Assert.assertTrue(cptBaseInfo.getCptId().intValue() < 3000000);

    }

    /**
     * case： cptJsonSchema too long.
     */
    @Test
    public void testRegisterCpt_cptJsonSchemaValueIsTooLong()
        throws JsonProcessingException, IOException {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);

        StringBuffer value = new StringBuffer("");
        for (int i = 0; i < 5000; i++) {
            value.append("x");
        }

        HashMap<String, Object> cptJsonSchema = TestBaseUtil.buildCptJsonSchema();
        cptJsonSchema.put(JsonSchemaConstant.TITLE_KEY, value.toString());
        cptMapArgs.setCptJsonSchema(cptJsonSchema);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.CPT_JSON_SCHEMA_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptPublisher is blank.
     */
    @Test
    public void testRegisterCpt_cptPublisherNull() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().setWeId(null);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptPublisher is blank.
     */
    @Test
    public void testRegisterCpt_cptPublisherBlank() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().setWeId("");

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptPublisher is invalid.
     */
    @Test
    public void testRegisterCpt_invalidCptPublisher() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().setWeId("did:weid:0x!@#$%^&*()-+?.,中国");

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptPublisherPrivateKey is null.
     */
    @Test
    public void testRegisterCpt_priKeyNull() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().setWeIdPrivateKey(null);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： privateKey is null.
     */
    @Test
    public void testRegisterCpt_setPriKeyNull() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().getWeIdPrivateKey().setPrivateKey(null);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptPublisherPrivateKey is null.
     */
    @Test
    public void testRegisterCpt_priKeyBlank() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().getWeIdPrivateKey().setPrivateKey("");

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： privateKey is invalid.
     */
    @Test
    public void testRegisterCpt_invalidPriKey() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().getWeIdPrivateKey()
            .setPrivateKey("123~!@#$%^&*()-+=？》《中国OIU");

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： privateKey is new privateKey.
     */
    @Test
    public void testRegisterCpt_newPriKey() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().setWeIdPrivateKey(
            TestBaseUtil.createEcKeyPair().getPrivateKey());

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： privateKey is SDK privateKey.
     */
    @Test
    public void testRegisterCpt_sdkPriKey() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().setWeIdPrivateKey(privateKey);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptPublisher is not exists and the private key is match.
     */
    @Test
    public void testRegisterCpt_cptPublisherNotExist() {

        PasswordKey passwordKey = TestBaseUtil.createEcKeyPair();
        String weId = WeIdUtils.convertPublicKeyToWeId(passwordKey.getPublicKey());

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().setWeId(weId);
        cptMapArgs.getWeIdAuthentication()
            .setWeIdPrivateKey(passwordKey.getPrivateKey());

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.CPT_PUBLISHER_NOT_EXIST.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： build cpt string.
     */
    @Test
    public void testRegisterCptCase20() throws IOException {

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, false);
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * case： build cpt string, args is null.
     */
    @Test
    public void testRegisterCptCase21() {

        CptStringArgs cptStringArgs = null;
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： build cpt string for unkonw_error.
     */
    @Test
    public void testRegisterCptCase22() throws IOException {

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, false);
        cptStringArgs.setCptJsonSchema("xxxxx");
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        LogUtil.info(logger, "registerCpt", response);

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
    public void testRegisterCptCase23() throws IOException {

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, true);
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * case： WeIdAuthentication is null.
     */
    @Test
    public void testRegisterCpt_weIdAuthenticationNull() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.setWeIdAuthentication(null);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(
            ErrorCode.WEID_AUTHORITY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： WeIdAuthentication is blank.
     */
    @Test
    public void testRegisterCpt_weIdAuthenticationBlank() {

        WeIdAuthentication weIdAuthentication = new WeIdAuthentication();
        CptMapArgs cptMapArgs = new CptMapArgs();
        cptMapArgs.setWeIdAuthentication(weIdAuthentication);
        cptMapArgs.setCptJsonSchema(new HashMap<>());

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(
            ErrorCode.WEID_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case: call transactionhex method - arbitrary.
     */
    @Test
    public void testRegisterCptCase28() {
        String hex = StringUtils.EMPTY;
        RawTransactionService rawTransactionService = new RawTransactionServiceImpl();
        ResponseData<String> response = rawTransactionService.registerCpt(hex);
        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(),
            response.getErrorCode().intValue());
        Assert.assertTrue(StringUtils.isEmpty(response.getResult()));
    }

    /**
     * case: call transactionhex method - arbitrary.
     */
    @Test
    public void testRegisterCptCase29() {
        String hex = "11111";
        RawTransactionService rawTransactionService = new RawTransactionServiceImpl();
        ResponseData<String> response = rawTransactionService.registerCpt(hex);
        Assert.assertEquals(ErrorCode.TRANSACTION_EXECUTE_ERROR.getCode(),
            response.getErrorCode().intValue());
        Assert.assertTrue(StringUtils.isEmpty(response.getResult()));
    }

}
