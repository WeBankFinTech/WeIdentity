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

package com.webank.weid.service.impl.engine;

import java.util.List;

import com.webank.weid.protocol.base.WeIdDocument;
import com.webank.weid.protocol.base.WeIdPojo;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.base.WeIdPublicKey;
import com.webank.weid.protocol.response.ResponseData;

/**
 * this service engine calls the contract methods and process blockchain response data on FISCO BCOS
 * 1.3.x or on FISCO BCOS 2.0.
 *
 * @author tonychen 2019年6月21日
 */
public interface WeIdServiceEngine extends ReloadStaticContract {

    /**
     * call weid contract to create a new weid.
     *
     * @param weAddress identity on blockchain
     * @param publicKey public key of the identity
     * @param privateKey privateKey identity's private key
     * @param isDelegate true if the caller is a delegate
     * @return result
     */
    ResponseData<Boolean> createWeId(
        String weAddress,
        WeIdPublicKey publicKey,
        WeIdPrivateKey privateKey,
        boolean isDelegate
    );

    /**
     * write attribute to blockchain.
     *
     * @param weAddress identity on blockchain
     * @param attributeKey the key of the attribute
     * @param value the value of the attribute
     * @param privateKey identity's private key
     * @param isDelegate true if the caller is a delegate
     * @return result
     */
    ResponseData<Boolean> setAttribute(
        String weAddress,
        String attributeKey,
        String value,
        WeIdPrivateKey privateKey,
        boolean isDelegate
    );

    /**
     * check if the weid exists on blockchain.
     *
     * @param weId the weid of the entity
     * @return result
     */
    ResponseData<Boolean> isWeIdExist(String weId);

    /**
     * get weid document from blockchain.
     *
     * @param weId the entity's weid
     * @return weid document
     */
    ResponseData<WeIdDocument> getWeIdDocument(String weId);

    /**
     * query data according to block height, index location and search direction.
     * 
     * @param blockNumber the query blockNumber
     * @param pageSize the page size
     * @param indexInBlock the beginning (including) of the current block
     * @param direction search direction: true means forward search, false means backward search
     * @return return the WeIdPojo List
     * @throws Exception unknown exception
     */
    ResponseData<List<WeIdPojo>> getWeIdList(
        Integer blockNumber,
        Integer pageSize,
        Integer indexInBlock,
        boolean direction
    ) throws Exception;
    
    /**
     * get total weId.
     *
     * @return total weid
     */
    ResponseData<Integer> getWeIdCount();
}
