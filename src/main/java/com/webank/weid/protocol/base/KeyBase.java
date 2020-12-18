package com.webank.weid.protocol.base;

import java.math.BigInteger;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.utils.Numeric;

import com.webank.weid.constant.KeyType;
import com.webank.weid.util.DataToolUtils;

public class KeyBase {

    protected byte[] value;

    private KeyType analysisKeyType(String key) {
        if (StringUtils.isBlank(key)) {
            return null;
        }
        if (StringUtils.isNumeric(key)) {
            return KeyType.BIGINT;
        } else if (DataToolUtils.isHexNumberRex(key)) {
            return KeyType.HEX;
        } else if (DataToolUtils.isValidBase64String(key)) {
            return KeyType.BASE64;
        }
        return null;
    }

    protected void setValue(byte[] value) {
        this.value = value;
    }

    protected void keyToBytes(String key) {
        this.value = null;
        if (StringUtils.isBlank(key)) {
            return;
        }
        KeyType type = this.analysisKeyType(key);
        if (type == KeyType.BIGINT) {
            this.value = new BigInteger(key, 10).toByteArray();
        } else if (type == KeyType.BASE64) {
            this.value = Base64.decodeBase64(key);
        } else if (type == KeyType.HEX) {
            this.value = Numeric.hexStringToByteArray(key);
        }
    }

    /**
     * 秘钥转字节数组.
     * @return 返回秘钥字节数组
     */
    public byte[] toBytes() {
        return this.value;
    }

    /**
     *秘钥转16进制数据.
     * @return 返回16进制字符串数据
     */
    public String toHex() {
        if (this.value == null) {
            return StringUtils.EMPTY;
        }
        return Numeric.toHexStringNoPrefix(this.value);
    }

    /**
     * 秘钥转Base64格式.
     * @return 返回Base64格式数据
     */
    public String toBase64() {
        if (this.value == null) {
            return StringUtils.EMPTY;
        }
        return Base64.encodeBase64String(this.value);
    }
}
