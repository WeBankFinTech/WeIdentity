/*
 *       Copyright© (2018-2020) WeBank Co., Ltd.
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

package com.webank.weid.suite.crypto;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import com.webank.wedpr.ecies.EciesResult;
import com.webank.wedpr.ecies.NativeInterface;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.utils.Numeric;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.exception.EncodeSuiteException;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.base.WeIdPublicKey;
import com.webank.weid.suite.api.crypto.inf.CryptoService;
import com.webank.weid.util.DataToolUtils;

public class EciesCryptoService implements CryptoService {

    private static final Logger logger = LoggerFactory.getLogger(EciesCryptoService.class);

    @Override
    public String encrypt(String content, String key) throws EncodeSuiteException {
        logger.info("begin encrypt by ecies.");
        checkForEncrypt(content, key);
        String data = Numeric.toHexStringNoPrefix(content.getBytes(StandardCharsets.UTF_8));
        WeIdPublicKey weIdPublicKey = new WeIdPublicKey(key);
        EciesResult result =  NativeInterface.eciesEncrypt(weIdPublicKey.toHex(), data); // 加密
        if (result != null) {
            if (StringUtils.isBlank(result.wedprErrorMessage)) {
                logger.info("encrypt by ecies successfully.");
                return Base64.encodeBase64String(
                    Numeric.hexStringToByteArray(result.encryptMessage));
            }
            logger.error("encrypt by ecies fail, message = {}.", result.wedprErrorMessage);
            throw new EncodeSuiteException(result.wedprErrorMessage);
        }
        throw new EncodeSuiteException(ErrorCode.UNKNOW_ERROR);
    }

    private void checkForEncrypt(String content, String key) {
        check(content, key);
        // 检查content是否为utf-8
        boolean isUtf8 = Charset.forName(StandardCharsets.UTF_8.toString())
            .newEncoder().canEncode(content);
        if (!isUtf8) {
            String errorMessage = "input content is not utf-8.";
            throw new EncodeSuiteException(ErrorCode.ILLEGAL_INPUT, errorMessage);
        }
    }

    @Override
    public String decrypt(String content, String key) throws EncodeSuiteException {
        logger.info("begin decrypt by ecies.");
        checkForDecrypt(content, key);
        String data = Numeric.toHexStringNoPrefix(Base64.decodeBase64(content));
        WeIdPrivateKey weIdPrivateKey = new WeIdPrivateKey(key);
        EciesResult deResult =  NativeInterface.eciesDecrypt(weIdPrivateKey.toHex(), data);
        if (deResult != null) {
            if (StringUtils.isBlank(deResult.wedprErrorMessage)) {
                logger.info("decrypt by ecies successfully.");
                byte[] buffer = Numeric.hexStringToByteArray(deResult.decryptMessage);
                return new String(buffer, StandardCharsets.UTF_8);
            }
            logger.error("decrypt by ecies fail, message = {}.", deResult.wedprErrorMessage);
            throw new EncodeSuiteException(deResult.wedprErrorMessage);
        }
        throw new EncodeSuiteException(ErrorCode.UNKNOW_ERROR);
    }

    private void checkForDecrypt(String content, String key) {
        check(content, key);
        // 检查content是否为标准base64格式
        if (!DataToolUtils.isValidBase64String(content)) {
            String errorMessage = "input content is not a valid Base64 string.";
            throw new EncodeSuiteException(ErrorCode.ILLEGAL_INPUT, errorMessage);
        }
    }

    private static void check(String content, String key) {
        // 入参非空检查
        String errorMessage = null;
        if (StringUtils.isEmpty(content)) {
            errorMessage = "input content is null.";
            throw new EncodeSuiteException(ErrorCode.ILLEGAL_INPUT, errorMessage);
        }
        // 入参非空检查
        if (StringUtils.isEmpty(key)) {
            errorMessage = "input key is null.";
            throw new EncodeSuiteException(ErrorCode.ILLEGAL_INPUT, errorMessage);
        }
    }
}
