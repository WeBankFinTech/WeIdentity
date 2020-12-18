/*
 *       Copyright© (2019) WeBank Co., Ltd.
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

import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.full.TestBaseService;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;

/**
 * Test most cases of Specific Issuers.
 *
 * @author chaoxinhu
 */
public class TestSpecificIssuer extends TestBaseService {

    private static String defaultType = "testCollege";

    @Test
    public void integrationSpecificIssuerTest() {
        // register an issue type (may already exist)
        WeIdAuthentication weIdAuthentication = TestBaseUtil.buildWeIdAuthority(createWeIdResult);
        ResponseData<Boolean> response1 =
            authorityIssuerService.registerIssuerType(weIdAuthentication, defaultType);
        Assert.assertTrue(response1.getResult() || (response1.getErrorCode()
            == ErrorCode.SPECIFIC_ISSUER_CONTRACT_ERROR_ALREADY_EXISTS.getCode()));

        CreateWeIdDataResult weIdResult = weIdService.createWeId().getResult();

        // add a WeId as an issuer into it with plain private key
        weIdAuthentication = new WeIdAuthentication();
        weIdAuthentication.setWeId(weIdResult.getWeId());
        weIdAuthentication.setWeIdPrivateKey(weIdResult.getUserWeIdPrivateKey());
        ResponseData<Boolean> response2 = authorityIssuerService
            .addIssuerIntoIssuerType(weIdAuthentication, defaultType, weIdResult.getWeId());
        Assert.assertEquals(response2.getErrorCode().intValue(),
            ErrorCode.CONTRACT_ERROR_NO_PERMISSION.getCode());

        // use the correct (SDK) private key to register
        weIdAuthentication.setWeIdPrivateKey(new WeIdPrivateKey());
        weIdAuthentication.getWeIdPrivateKey().setPrivateKey(privateKey.getPrivateKey());
        ResponseData<Boolean> response3 = authorityIssuerService
            .addIssuerIntoIssuerType(weIdAuthentication, defaultType, weIdResult.getWeId());
        Assert.assertTrue(response3.getResult());

        // check the chain to see if this guy is already there
        ResponseData<Boolean> response4 = authorityIssuerService
            .isSpecificTypeIssuer(defaultType, weIdResult.getWeId());
        Assert.assertTrue(response4.getResult());

        // remove this WeId
        ResponseData<Boolean> response5 = authorityIssuerService
            .removeIssuerFromIssuerType(weIdAuthentication, defaultType, weIdResult.getWeId());
        Assert.assertTrue(response5.getResult());
        ResponseData<Boolean> response6 = authorityIssuerService
            .isSpecificTypeIssuer(defaultType, weIdResult.getWeId());
        Assert.assertFalse(response6.getResult());
    }

    @Test
    public void integrationSpecificIssuerListTest() {
        // register an issue type (may already exist)
        WeIdAuthentication weIdAuthentication = TestBaseUtil.buildWeIdAuthority(createWeIdResult);
        ResponseData<Boolean> response1 =
            authorityIssuerService.registerIssuerType(weIdAuthentication, defaultType);
        Assert.assertTrue(response1.getResult() || (response1.getErrorCode()
            == ErrorCode.SPECIFIC_ISSUER_CONTRACT_ERROR_ALREADY_EXISTS.getCode()));

        CreateWeIdDataResult weIdResult1 = weIdService.createWeId().getResult();

        weIdAuthentication = new WeIdAuthentication();
        weIdAuthentication.setWeId(weIdResult1.getWeId());
        weIdAuthentication.setWeIdPrivateKey(new WeIdPrivateKey());
        weIdAuthentication.getWeIdPrivateKey().setPrivateKey(privateKey.getPrivateKey());
        ResponseData<Boolean> response2 = authorityIssuerService
            .addIssuerIntoIssuerType(weIdAuthentication, defaultType, weIdResult1.getWeId());
        Assert.assertTrue(response2.getResult());
        CreateWeIdDataResult weIdResult2 = weIdService.createWeId().getResult();
        ResponseData<Boolean> response3 = authorityIssuerService
            .addIssuerIntoIssuerType(weIdAuthentication, defaultType, weIdResult2.getWeId());
        Assert.assertTrue(response3.getResult());
        ResponseData<List<String>> respData = authorityIssuerService
            .getAllSpecificTypeIssuerList(defaultType, 0, 2);
        Assert.assertNotNull(respData.getResult());
        // We should be able to fetch at least 2 elements
        Assert.assertEquals(respData.getResult().size(), 2);

        // Try to fetch max number of elements and it should not return failure
        ResponseData<List<String>> respData2 = authorityIssuerService
            .getAllSpecificTypeIssuerList(defaultType, 999999,
                WeIdConstant.MAX_AUTHORITY_ISSUER_LIST_SIZE);
        ResponseData<List<String>> respData3 = authorityIssuerService
            .getAllSpecificTypeIssuerList(defaultType, 0,
                WeIdConstant.MAX_AUTHORITY_ISSUER_LIST_SIZE);
        Assert.assertNotNull(respData2.getResult());
        Assert.assertEquals(respData2.getResult().size(), 0);
        Assert.assertNotNull(respData3.getResult());
        Assert.assertTrue(respData3.getResult().size() > 0);
        ResponseData<Boolean> response4 = authorityIssuerService
            .removeIssuerFromIssuerType(weIdAuthentication, defaultType, weIdResult1.getWeId());
        ResponseData<Boolean> response5 = authorityIssuerService
            .removeIssuerFromIssuerType(weIdAuthentication, defaultType, weIdResult2.getWeId());
        Assert.assertTrue(response4.getResult());
        Assert.assertTrue(response5.getResult());
    }
}
