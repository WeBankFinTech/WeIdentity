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
 * The base data wrapper to handle WeIdentity DID Public Key info.
 *
 * <p>Created by Junqi Zhang on 18/10/2018.
 */
public class WeIdPublicKey extends KeyBase {

    /**
     * Required: The public key.
     */
    @Getter
    private String publicKey;

    public WeIdPublicKey() {
        super();
    }

    public WeIdPublicKey(byte[] value) {
        super.setValue(value);
        this.publicKey = super.toHex();
    }

    public WeIdPublicKey(String publicKey) {
        setPublicKey(publicKey);
    }

    public void setPublicKey(String publicKey) {
        super.keyToBytes(publicKey);
        this.publicKey = super.toHex();
    }
    
    @Override
    public String toString() {
        return "WeIdPublicKey(publicKey=" + this.publicKey + ")";
    }
}
