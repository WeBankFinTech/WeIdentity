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

package com.webank.weid.full.auth;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.full.TestBaseService;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.AuthorityIssuer;
import com.webank.weid.protocol.request.RegisterAuthorityIssuerArgs;
import com.webank.weid.protocol.request.RemoveAuthorityIssuerArgs;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.util.DateUtils;

/**
 * queryAuthorityIssuerInfo method for testing AuthorityIssuerService.
 *
 * @author v_wbgyang/rockyxia
 */
public class TestQueryAuthorityIssuerInfo extends TestBaseService {

    private static final Logger logger =
        LoggerFactory.getLogger(TestQueryAuthorityIssuerInfo.class);

    private static CreateWeIdDataResult createWeId;

    @Override
    public synchronized void testInit() {

        super.testInit();
        if (createWeId == null) {
            createWeId = super.registerAuthorityIssuer();
        }
    }

    /**
     * case: query success.
     */
    @Test
    public void testQueryAuthorityIssuerInfo_success() {

        ResponseData<AuthorityIssuer> response =
            authorityIssuerService.queryAuthorityIssuerInfo(createWeId.getWeId());
        LogUtil.info(logger, "queryAuthorityIssuerInfo", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * case: WeIdentity DID is null.
     */
    @Test
    public void testQueryAuthorityIssuerInfo_weIdNull() {

        ResponseData<AuthorityIssuer> response =
            authorityIssuerService.queryAuthorityIssuerInfo(null);
        LogUtil.info(logger, "queryAuthorityIssuerInfo", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case: WeIdentity DID is blank.
     */
    @Test
    public void testQueryAuthorityIssuerInfo_weIdBlank() {

        ResponseData<AuthorityIssuer> response =
            authorityIssuerService.queryAuthorityIssuerInfo("");
        LogUtil.info(logger, "queryAuthorityIssuerInfo", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case: WeIdentity DID is bad format.
     */
    @Test
    public void testQueryAuthorityIssuerInfo_weIdFormat() {

        ResponseData<AuthorityIssuer> response =
            authorityIssuerService.queryAuthorityIssuerInfo("xx:xx:xxxxxxx");
        LogUtil.info(logger, "queryAuthorityIssuerInfo", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case: WeIdentity DID is invalid.
     */
    @Test
    public void testQueryAuthorityIssuerInfo_invalidWeId() {

        ResponseData<AuthorityIssuer> response = authorityIssuerService
            .queryAuthorityIssuerInfo("123!@#$%^&*()/.,,-=+gt中国yyyyyy$%^&*fsdfdfdfdd");
        LogUtil.info(logger, "queryAuthorityIssuerInfo", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case: WeIdentity DID is not exists.
     */
    @Test
    public void testQueryAuthorityIssuerInfo_weIdNotExist() {

        ResponseData<AuthorityIssuer> response = authorityIssuerService
            .queryAuthorityIssuerInfo("did:weid:0xc7e399b8d2da337f4e92eb33ca88b60b899b5022");
        LogUtil.info(logger, "queryAuthorityIssuerInfo", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NOT_EXISTS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case: WeIdentity DID is not registed.
     */
    @Test
    public void testQueryAuthorityIssuerInfo_weIdNotRegister() {

        String weId = createWeId().getWeId();
        ResponseData<AuthorityIssuer> response = authorityIssuerService
            .queryAuthorityIssuerInfo(weId);
        LogUtil.info(logger, "queryAuthorityIssuerInfo", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NOT_EXISTS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case: WeIdentity DID is removed then query.
     */
    @Test
    public void testQueryAuthorityIssuerInfo_weIdRemoved() {

        CreateWeIdDataResult createWeId = super.registerAuthorityIssuer();
        LogUtil.info(logger, "registerAuthorityIssuer", createWeId);

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs =
            TestBaseUtil.buildRemoveAuthorityIssuerArgs(createWeId, privateKey);

        ResponseData<Boolean> response =
            authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        LogUtil.info(logger, "removeAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());

        ResponseData<AuthorityIssuer> response1 =
            authorityIssuerService.queryAuthorityIssuerInfo(createWeId.getWeId());
        LogUtil.info(logger, "queryAuthorityIssuerInfo", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NOT_EXISTS.getCode(),
            response1.getErrorCode().intValue());
        Assert.assertNull(response1.getResult());
    }

    /**
     * case: register issuer that create time is after now, then query the issuer.
     */
    @Test
    public void testQueryAuthorityIssuerInfo_createFuture() {

        String weId = createWeId().getWeId();
        AuthorityIssuer authorityIssuer = new AuthorityIssuer();
        authorityIssuer.setWeId(weId);
        authorityIssuer.setName("zhbank" + Math.random());
        authorityIssuer.setAccValue("0");
        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs = new RegisterAuthorityIssuerArgs();
        registerAuthorityIssuerArgs.setAuthorityIssuer(authorityIssuer);
        registerAuthorityIssuerArgs.setWeIdPrivateKey(privateKey);
        registerAuthorityIssuerArgs.getAuthorityIssuer()
            .setCreated(DateUtils.getNoMillisecondTimeStamp() + 1000000);

        ResponseData<Boolean> response =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        LogUtil.info(logger, "registerAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());

        ResponseData<AuthorityIssuer> response1 =
            authorityIssuerService.queryAuthorityIssuerInfo(weId);
        LogUtil.info(logger, "queryAuthorityIssuerInfo", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(),
            response1.getErrorCode().intValue());
        Assert.assertNotNull(response1.getResult());
    }
}
