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

package com.webank.weid.suite.api.crypto.params;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.utils.Numeric;

import com.webank.weid.util.DataToolUtils;

/**
 * 秘钥生成器.
 * @author v_wbgyang
 *
 */
public class KeyGenerator {
    
    public static final int DEFAULT_KEY_SIZE = 1024;
    public static final int PUBLIC_KEY_LENGTH_IN_HEX = 128;
    public static final int PRIVATE_KEY_LENGTH_IN_HEX = 64;

    /**
     * 使用UUID作为秘钥.
     * @return 返回UUID字符串
     */
    public static String getKey() {
        return DataToolUtils.getUuId32();   
    }
    
    /**
     * 生成RSA非对称加密密钥.
     * @return 返回Asymmetrickey 非对此秘钥
     * @throws NoSuchAlgorithmException 找不到Algorithm异常
     */
    public static Asymmetrickey getKeyForRsa() throws NoSuchAlgorithmException {
        return getKeyForRsa(DEFAULT_KEY_SIZE);
    }
    
    /**
     * 生成RSA非对称加密密钥.
     * @param keySize 密钥对大小范围
     * @return 返回Asymmetrickey 非对此秘钥
     * @throws NoSuchAlgorithmException 找不到Algorithm异常
     */
    public static Asymmetrickey getKeyForRsa(int keySize) throws NoSuchAlgorithmException {
        // KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(CryptoType.RSA.name());
        // 初始化密钥对生成器，密钥大小单位为位
        keyPairGen.initialize(keySize, new SecureRandom());
        // 生成一个密钥对，保存在keyPair中
        KeyPair keyPair = keyPairGen.generateKeyPair();
        String pub = new String(
            Base64.encodeBase64(keyPair.getPublic().getEncoded()), 
            StandardCharsets.UTF_8
        );
        String pri = new String(
            Base64.encodeBase64(keyPair.getPrivate().getEncoded()),
            StandardCharsets.UTF_8
        );
        Asymmetrickey key = new Asymmetrickey();
        key.setPrivavteKey(pri);
        key.setPublicKey(pub);
        return key;
    }
    
    /**
     * 将WeId生成的10进制密钥转换成可以加解密的Base64密钥.
     * @param decimalKey 10进制的数字密钥
     * @return 返回补位后的base64密钥
     */
    public static String decimalKeyToBase64(String decimalKey) {
        if (!StringUtils.isNumeric(decimalKey)) {
            return StringUtils.EMPTY;
        }
        BigInteger bigInt = new BigInteger(decimalKey, 10);
        return Base64.encodeBase64String(bigInt.toByteArray());
    }
    
    /**
     * 将Base64类型的密钥转换成10进制的数字密钥.
     * @param base64Key Base64类型密钥
     * @return 返回10进制的数字密钥
     */
    public static String base64KeyTodecimal(String base64Key) {
        if (!DataToolUtils.isValidBase64String(base64Key)) {
            return StringUtils.EMPTY; 
        }
        return Numeric.toBigInt(Base64.decodeBase64(base64Key)).toString();
    }
}
