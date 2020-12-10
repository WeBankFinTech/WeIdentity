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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.fisco.bcos.sdk.abi.datatypes.DynamicArray;
import org.fisco.bcos.sdk.abi.datatypes.DynamicBytes;
import org.fisco.bcos.sdk.abi.datatypes.StaticArray;
import org.fisco.bcos.sdk.abi.datatypes.generated.Bytes32;
import org.fisco.bcos.sdk.abi.datatypes.generated.Int256;
import org.fisco.bcos.sdk.abi.datatypes.generated.Uint256;
import org.fisco.bcos.sdk.abi.datatypes.generated.Uint8;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.WeIdConstant;

/**
 * test DataToolUtils.
 *
 * @author v_wbjnzhang
 */
public class TestDataTypetUtils {

    private static final Logger logger = LoggerFactory.getLogger(TestDataTypetUtils.class);

    @Test
    public void testBytesArrayToBytes32() {

        byte[] bytes1 = new byte[32];
        Bytes32 result = DataToolUtils.bytesArrayToBytes32(bytes1);
        Assert.assertNotNull(result);
    }

    @Test
    public void testStringToBytes32() {

        String str = "abcdefghijklmnopqrstuvwxyzABCDEF";// length is 32
        Bytes32 result = DataToolUtils.stringToBytes32(str);
        Assert.assertNotNull(result);
    }

    @Test
    public void testBytes32ToBytesArray() {

        String str = "abcdefghijklmnopqrstuvwxyzABCDEF";
        Bytes32 bytes32 = DataToolUtils.stringToBytes32(str);
        byte[] result = DataToolUtils.bytes32ToBytesArray(bytes32);
        Assert.assertNotNull(result);
    }

    @Test
    public void testBytes32ToString() {

        String str = "abcdefghijklmnopqrstuvwxyzABCDEF";
        Bytes32 bytes32 = DataToolUtils.stringToBytes32(str);
        String result = DataToolUtils.bytes32ToString(bytes32);
        Assert.assertEquals(result, str);

        str = "";
        bytes32 = DataToolUtils.stringToBytes32(str);
        result = DataToolUtils.bytes32ToString(bytes32);
        Assert.assertEquals(result, str);

        str = " slfjds ljlfs ";
        bytes32 = DataToolUtils.stringToBytes32(str);
        result = DataToolUtils.bytes32ToString(bytes32);
        Assert.assertEquals(result, str.trim());
    }

    @Test
    public void testBytes32ToStringWithoutTrim() {

        String str = "abcdefghijklmnopqrstuvwxyzABCDEF";// length is 32
        Bytes32 bytes32 = DataToolUtils.stringToBytes32(str);
        String result = DataToolUtils.bytes32ToStringWithoutTrim(bytes32);
        Assert.assertEquals(result, str);

        str = "";
        bytes32 = DataToolUtils.stringToBytes32(str);
        result = DataToolUtils.bytes32ToStringWithoutTrim(bytes32);
        Assert.assertEquals(result.length(), 32);

        str = " slfjds ljlfs ";
        bytes32 = DataToolUtils.stringToBytes32(str);
        result = DataToolUtils.bytes32ToStringWithoutTrim(bytes32);
        Assert.assertEquals(result.length(), 32);
    }

    @Test
    public void testIntToUint256() {

        int n = 0;
        Uint256 result = DataToolUtils.intToUint256(n);
        int m = DataToolUtils.uint256ToInt(result);
        Assert.assertEquals(n, m);

        n = 9999999;
        result = DataToolUtils.intToUint256(n);
        m = DataToolUtils.uint256ToInt(result);
        Assert.assertEquals(n, m);
    }

    @Test
    public void testIntToInt256() {

        int n = 0;
        Int256 result = DataToolUtils.intToInt256(n);
        int m = DataToolUtils.int256ToInt(result);
        Assert.assertEquals(n, m);

        n = 9999999;
        result = DataToolUtils.intToInt256(n);
        m = DataToolUtils.int256ToInt(result);
        Assert.assertEquals(n, m);

        n = -9999999;
        result = DataToolUtils.intToInt256(n);
        m = DataToolUtils.int256ToInt(result);
        Assert.assertEquals(n, m);
    }

    @Test
    public void testLongToInt256() {

        long n = 0L;
        Int256 result = DataToolUtils.longToInt256(n);
        long m = DataToolUtils.int256ToLong(result);
        Assert.assertEquals(n, m);

        n = 999999999999999L;
        result = DataToolUtils.longToInt256(n);
        m = DataToolUtils.int256ToLong(result);
        Assert.assertEquals(n, m);

        n = -999999999999999L;
        result = DataToolUtils.longToInt256(n);
        m = DataToolUtils.int256ToLong(result);
        Assert.assertEquals(n, m);
    }

    @Test
    public void testLongArrayToInt256StaticArray() {

        long[] array = {8L, 5555L, 64L, 0L, -147L};
        StaticArray<Int256> result = DataToolUtils.longArrayToInt256StaticArray(array);
        DynamicArray<Int256> result1 = new DynamicArray<Int256>(result.getValue());

        long[] array1 = DataToolUtils.int256DynamicArrayToLongArray(result1);
        for (int i = 0; i < array.length; i++) {
            Assert.assertEquals(array[i], array1[i]);
        }
    }

    @Test
    public void teststringArrayToBytes32StaticArray() {

        String[] array = {"book", "student", "person", "apple"};
        StaticArray<Bytes32> result = DataToolUtils.stringArrayToBytes32StaticArray(array);
        DynamicArray<Bytes32> result1 = new DynamicArray<Bytes32>(result.getValue());

        String[] array1 = DataToolUtils.bytes32DynamicArrayToStringArrayWithoutTrim(result1);
        for (int i = 0; i < array.length; i++) {
            logger.info("---{}----", array1[i]);
        }
        Assert.assertNotNull(array1);
    }

    @Test
    public void testIntToUint8() {

        int n = 0;
        Uint8 result = DataToolUtils.intToUnt8(n);
        int m = DataToolUtils.uint8ToInt(result);
        Assert.assertEquals(n, m);
        n = 255;
        result = DataToolUtils.intToUnt8(n);
        m = DataToolUtils.uint8ToInt(result);
        Assert.assertEquals(n, m);
    }

    @Test
    public void testStringToDynamicBytes() {

        String str = "";
        DynamicBytes result = DataToolUtils.stringToDynamicBytes(str);
        String newstr = DataToolUtils.dynamicBytesToString(result);
        Assert.assertEquals(str, newstr);

        str = "dssfdsgs";
        result = DataToolUtils.stringToDynamicBytes(str);
        newstr = DataToolUtils.dynamicBytesToString(result);
        Assert.assertEquals(str, newstr);

        str = "  dssfdsdd   gs  ";
        result = DataToolUtils.stringToDynamicBytes(str);
        newstr = DataToolUtils.dynamicBytesToString(result);
        Assert.assertEquals(str, newstr);

        str = "aaaaaaaaaabbbbbbbbbbccccccccccddaaaa";
        result = DataToolUtils.stringToDynamicBytes(str);
        newstr = DataToolUtils.dynamicBytesToString(result);
        Assert.assertEquals(str, newstr);
    }

    @Test
    public void testHashConversion() {
        String hash = DataToolUtils.sha3(UUID.randomUUID().toString());
        byte[] convertedHash = DataToolUtils.convertHashStrIntoHashByte32Array(hash);
        Assert.assertEquals(convertedHash.length, WeIdConstant.BYTES32_FIXED_LENGTH.intValue());
        String convertedBackStr = DataToolUtils
            .convertHashByte32ArrayIntoHashStr(convertedHash);
        Assert.assertEquals(hash, convertedBackStr);
        Assert.assertEquals(hash.length(), WeIdConstant.BYTES32_FIXED_LENGTH * 2 + 2);
        List<String> listX = new ArrayList(
            Arrays.asList("a", "b", "c", "d", "f", "f", "g"));
        List<String> listY = new ArrayList(Arrays.asList("a", "c", "f", "f", "g"));
        List<Boolean> result = DataToolUtils.strictCheckExistence(listX, listY);
        Assert.assertTrue(result.get(0) && result.get(2));
        Assert.assertFalse(result.get(1) || result.get(3));
        Assert.assertEquals(result.size(), 7);
    }
}
