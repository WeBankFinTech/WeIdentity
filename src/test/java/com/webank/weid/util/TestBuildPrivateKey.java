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

package com.webank.weid.util;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.PasswordKey;
import com.webank.weid.full.TestBaseUtil;

/**
 * the role of this class is to handle the private key required in the testing process.
 *
 * @author v_wbgyang
 */
public class TestBuildPrivateKey {

    private static final Logger logger = LoggerFactory.getLogger(TestBuildPrivateKey.class);

    /**
     * extract the private key in org1.txt and transform it into 16 binary system
     */
    @Test
    public void testBuildPrivateKey() {
        PasswordKey passwordKey = TestBaseUtil.resolvePk("org1.txt");
        String str1 = passwordKey.getPrivateKey().getPrivateKey();
        logger.info("private key:{}", str1);
        Assert.assertNotNull(str1);
    }
}
