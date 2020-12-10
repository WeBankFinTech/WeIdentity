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

package com.webank.weid.util;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.PasswordKey;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.suite.api.crypto.CryptoServiceFactory;
import com.webank.weid.suite.api.crypto.params.Asymmetrickey;
import com.webank.weid.suite.api.crypto.params.CryptoType;
import com.webank.weid.suite.api.crypto.params.KeyGenerator;

public class TestCrypt {
    
    private static final Logger logger = LoggerFactory.getLogger(TestCrypt.class);
    
    private static String json = "{\"claim\":{\"a\":\"a\",\"b\":\"b\"},\"cptId\":2000099,"
            + "\"expirationDate\":1903510144,\"id\":\"4d4bb35e-6335-4e81-aae9-6a3b88ca04f3\","
            + "\"issuer\":\"did:weid:101:0x110f0ed41b33b1395b9060d274247c2f9e15b29a\","
            + "\"type\":\"lite1\"}";
    
    private static final String original = "{\"name\":\"zhangsan\",age:12}";
    
    @Test
    public void testAes() {
        String key = KeyGenerator.getKey();
        logger.info("key: {}", key);
        logger.info("original: {}", original);
        String encrypt = CryptoServiceFactory.getCryptoService(CryptoType.AES)
            .encrypt(original, key);
        logger.info("encrypt: {}", encrypt);
        String decrypt = CryptoServiceFactory.getCryptoService(CryptoType.AES)
            .decrypt(encrypt, key);
        logger.info("decrypt: {}", decrypt);
        Assert.assertEquals(original, decrypt);
    }

    @Test
    public void testRsa() throws Exception {
        Asymmetrickey key = KeyGenerator.getKeyForRsa(2048);
        logger.info("pub key: {}", key.getPublicKey());
        logger.info("pri key: {}", key.getPrivavteKey());
        logger.info("original: {}", original);
        String encrypt = CryptoServiceFactory.getCryptoService(CryptoType.RSA)
            .encrypt(original, key.getPublicKey());
        logger.info("encrypt: {}", encrypt);
        String decrypt = CryptoServiceFactory.getCryptoService(CryptoType.RSA)
            .decrypt(encrypt, key.getPrivavteKey());
        logger.info("decrypt: {}", decrypt);
        Assert.assertEquals(original, decrypt);
    }
    
    @Test
    @Ignore
    public void testEcies_withPadding() throws Exception {
        // 外围有padding操作
        for (int i = 0; i < 1000; i++) {
            PasswordKey createEcKeyPair = TestBaseUtil.createEcKeyPair();
            String publicKey = createEcKeyPair.getPublicKey();
            String privateKey = createEcKeyPair.getPrivateKey();
            String pubBase64 = KeyGenerator.decimalKeyToBase64(publicKey);
            String priBase64 = KeyGenerator.decimalKeyToBase64(privateKey);
            logger.info("pub key base64: {}", pubBase64);
            logger.info("pri key base64: {}", priBase64);
            String original = json;
            String encrypt = CryptoServiceFactory.getCryptoService(CryptoType.ECIES)
                .encrypt(original, pubBase64);
            logger.info("encrypt: {}", encrypt);
            String decrypt = CryptoServiceFactory.getCryptoService(CryptoType.ECIES)
                .decrypt(encrypt, priBase64);
            logger.info("decrypt: {}", decrypt);
            Assert.assertEquals(DataToolUtils.sha3(original), DataToolUtils.sha3(decrypt));
            Assert.assertEquals(original, decrypt);
        } 
    }
    
    @Test
    @Ignore
    public void testEcies_noPadding() throws Exception {
        // 外围没有padding操作
        for (int i = 0; i < 1000; i++) {
            PasswordKey createEcKeyPair = TestBaseUtil.createEcKeyPair();
            String publicKey = createEcKeyPair.getPublicKey();
            String privateKey = createEcKeyPair.getPrivateKey();
            logger.info("pub key: {}", publicKey);
            logger.info("pri key: {}", privateKey);
            String original = json;
            String encrypt = CryptoServiceFactory.getCryptoService(CryptoType.ECIES)
                .encrypt(original, publicKey);
            logger.info("encrypt: {}", encrypt);
            String decrypt = CryptoServiceFactory.getCryptoService(CryptoType.ECIES)
                .decrypt(encrypt, privateKey);
            logger.info("decrypt: {}", decrypt);
            Assert.assertEquals(DataToolUtils.sha3(original), DataToolUtils.sha3(decrypt));
            Assert.assertEquals(original, decrypt);
        } 
    }
    
    @Test
    public void testDecimalKey() throws Exception {
        for (int i = 0; i < 1000; i++) {
            PasswordKey createEcKeyPair = TestBaseUtil.createEcKeyPair();
            String publicKey = createEcKeyPair.getPublicKey();
            String privateKey = createEcKeyPair.getPrivateKey();
            String pubBase64 = KeyGenerator.decimalKeyToBase64(publicKey);
            String priBase64 = KeyGenerator.decimalKeyToBase64(privateKey);
            String decimalPubKey = KeyGenerator.base64KeyTodecimal(pubBase64);
            String decimalPriKey = KeyGenerator.base64KeyTodecimal(priBase64);
            Assert.assertEquals(DataToolUtils.sha3(publicKey), DataToolUtils.sha3(decimalPubKey));
            Assert.assertEquals(DataToolUtils.sha3(privateKey), DataToolUtils.sha3(decimalPriKey));
            Assert.assertEquals(publicKey, decimalPubKey);
            Assert.assertEquals(privateKey, decimalPriKey);
        } 
    }
}
