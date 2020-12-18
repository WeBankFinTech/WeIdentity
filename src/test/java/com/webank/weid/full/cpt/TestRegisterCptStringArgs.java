package com.webank.weid.full.cpt;

import java.io.IOException;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.full.TestBaseService;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.Cpt;
import com.webank.weid.protocol.base.CptBaseInfo;
import com.webank.weid.protocol.request.CptStringArgs;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;

public class TestRegisterCptStringArgs extends TestBaseService {

    private static final Logger logger = LoggerFactory.getLogger(TestRegisterCptStringArgs.class);

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
     * case： build cpt string.
     */
    @Test
    public void testRegisterCptStringArgs_success() throws IOException {

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, false);
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertTrue(response.getResult().getCptId() < 2000000);
    }

    /**
     * case： weId is not auth issuer.
     */
    @Test
    public void testRegisterCptStringArgs_notAuthIssuer() throws IOException {

        ResponseData<Boolean> isAuthIssuer = authorityIssuerService
            .isAuthorityIssuer(createWeIdNew.getWeId());
        if (isAuthIssuer.getResult()) {
            createWeIdNew = super.createWeId();
        }

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeIdNew, false);
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertTrue(response.getResult().getCptId() > 2000000);
    }

    /**
     * case： build cpt string, args is null.
     */
    @Test
    public void testRegisterStringCptArgs_stringCptArgsNull() {

        CptStringArgs cptStringArgs = null;
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： used string build cpt string .
     */
    @Test
    public void testRegisterStringCptArgs_CptJsonSchemaIsStr() throws IOException {

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
     * case： used string build cpt string .
     */
    @Test
    public void testRegisterStringCptArgs_CptJsonSchemaIsBlankMap() throws IOException {

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, false);
        cptStringArgs.setCptJsonSchema("{}");
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(
            ErrorCode.CPT_JSON_SCHEMA_INVALID.getCode(),
            response.getErrorCode().intValue()
        );
        Assert.assertNull(response.getResult());
    }

    /**
     * case： used string build cpt string .
     */
    @Test
    public void testRegisterStringCptArgs_CptJsonSchemaValueIsStr() throws IOException {

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, false);
        cptStringArgs.setCptJsonSchema("{\"name\":\"rocky\"}");
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(
            ErrorCode.SUCCESS.getCode(),
            response.getErrorCode().intValue()
        );
        Assert.assertTrue(response.getResult().getCptId() < 2000000);
    }

    /**
     * case： used string-int build cpt string .
     */
    @Test
    public void testRegisterStringCptArgs_CptJsonSchemaValueIsInt() throws IOException {

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, false);
        cptStringArgs.setCptJsonSchema("{\"age\":18}");
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(
            ErrorCode.SUCCESS.getCode(),
            response.getErrorCode().intValue()
        );
        Assert.assertTrue(response.getResult().getCptId() < 2000000);
    }

    /**
     * case： used string-list build cpt string .
     */
    @Test
    public void testRegisterStringCptArgs_CptJsonSchemaValueIsList() throws IOException {

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, false);
        cptStringArgs.setCptJsonSchema("{\"peoples\":[\"liBai\",\"dufu\"]}");
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(
            ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertTrue(response.getResult().getCptId() < 2000000);
    }

    /**
     * case： used string-list build cpt string .
     */
    @Test
    public void testRegisterStringCptArgs_CptJsonSchemaValueIsList2() throws IOException {

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, false);
        cptStringArgs.setCptJsonSchema("{\"peoples\":[\"liBai\",\"dufu\"，18]}");
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(
            ErrorCode.UNKNOW_ERROR.getCode(),
            response.getErrorCode().intValue()
        );
        Assert.assertNull(response.getResult());
    }

    /**
     * case： used string-map build cpt string .
     */
    @Test
    public void testRegisterStringCptArgs_CptJsonSchemaValueIsMap() throws IOException {

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, false);
        cptStringArgs.setCptJsonSchema("{\"peoples\":{\"liBai\":18,\"dufu\":20}}");
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(
            ErrorCode.SUCCESS.getCode(),
            response.getErrorCode().intValue()
        );
        Assert.assertTrue(response.getResult().getCptId() < 2000000);
    }

    /**
     * case： used nest string-map build cpt string .
     */
    @Test
    public void testRegisterStringCptArgs_CptJsonSchemaValueIsNestMap() throws IOException {

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, false);
        cptStringArgs.setCptJsonSchema(
            "{\"peoples\":{\"liBai\":{\"唐朝\":{\"age\":800},"
                + "\"des\":{\"\":\"best one\"}},\"dufu\":{}}}");
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(
            ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        ResponseData<Cpt> res = cptService.queryCpt(response.getResult().getCptId());
        LogUtil.info(logger, "registerCpt", res.getResult().toString());

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), res.getErrorCode().intValue());
        Assert.assertNotNull(res.getResult().getCptJsonSchema());
    }


    /**
     * case： build cpt string ,CptJsonSchema is null.
     */
    @Test
    public void testRegisterStringCptArgs_CptJsonSchemaNull() throws IOException {

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, false);
        cptStringArgs.setCptJsonSchema(null);
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(
            ErrorCode.UNKNOW_ERROR.getCode(),
            response.getErrorCode().intValue()
        );
        Assert.assertNull(response.getResult());
    }

    /**
     * case： build cpt string ,CptJsonSchema is blank.
     */
    @Test
    public void testRegisterStringCptArgs_CptJsonSchemaBlank() throws IOException {

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, false);
        cptStringArgs.setCptJsonSchema("");
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
    public void testRegisterStringCptArgs_fromFile() throws IOException {

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, true);
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        LogUtil.info(logger, "registerCpt", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }
}
