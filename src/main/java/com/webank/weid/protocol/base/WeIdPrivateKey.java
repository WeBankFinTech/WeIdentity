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

package com.webank.weid.protocol.base;

import lombok.Getter;

/**
 * The base data wrapper to handle WeIdentity DID Private Key info.
 *
 * <p>Created by Junqi Zhang on 17/10/2018.
 */
public class WeIdPrivateKey extends KeyBase {

    /**
     * Required: The private key.
     */
    @Getter
    private String privateKey;

    public WeIdPrivateKey() {
        super();
    }
    
    public WeIdPrivateKey(byte[] value) {
        super.setValue(value);
        this.privateKey = super.toHex();
    }
    
    public WeIdPrivateKey(String privateKey) {
        setPrivateKey(privateKey);
    }

    public void setPrivateKey(String privateKey) {
        super.keyToBytes(privateKey); 
        this.privateKey = super.toHex();
    }
    
    @Override
    public String toString() {
        return "WeIdPrivateKey(privateKey=" + this.privateKey + ")";
    }
}
