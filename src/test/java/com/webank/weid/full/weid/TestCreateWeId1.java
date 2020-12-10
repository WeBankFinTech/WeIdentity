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

package com.webank.weid.full.weid;

import java.security.NoSuchProviderException;

import mockit.Mock;
import mockit.MockUp;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.full.TestBaseService;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;

/**
 * non parametric createWeId method for testing WeIdService.
 *
 * @author v_wbgyang
 */
public class TestCreateWeId1 extends TestBaseService {

    private static final Logger logger = LoggerFactory.getLogger(TestCreateWeId1.class);

    /**
     * case: create WeId success.
     */
    @Test
    public void testCreateWeId_createSucess() {

        ResponseData<CreateWeIdDataResult> response = weIdService.createWeId();
        LogUtil.info(logger, "createWeId", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * case:run CreateWeId twice Will create two different WeId.
     */
    @Test
    public void testCreateWeId_doubleCreateSucess() {

        ResponseData<CreateWeIdDataResult> response = weIdService.createWeId();
        LogUtil.info(logger, "createWeId", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
        ResponseData<CreateWeIdDataResult> response1 = weIdService.createWeId();
        LogUtil.info(logger, "createWeId", response1);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response1.getErrorCode().intValue());
        Assert.assertNotNull(response1.getResult());
        Assert.assertNotEquals(response.getResult().getWeId(), response1.getResult().getWeId());
    }

}
