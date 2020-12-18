/*
 *       Copyright© (2020) WeBank Co., Ltd.
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

package com.webank.weid.suite.persistence.redis;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.collections4.CollectionUtils;
import org.redisson.api.BatchResult;
import org.redisson.api.RBatch;
import org.redisson.api.RBucket;
import org.redisson.api.RedissonClient;
import org.redisson.client.RedisException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.DataDriverConstant;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.protocol.request.TransactionArgs;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.suite.persistence.DefaultValue;
import com.webank.weid.util.DataToolUtils;

/**
 * redis操作辅助类.
 *
 * @author karenli
 */
public class RedisExecutor {

    private static final Logger logger = LoggerFactory.getLogger(RedisExecutor.class);

    /**
     * the split for value.
     */
    private static final String VALUE_SPLIT_CHAR = ":";

    private RedisDomain redisDomain;



    /**
     * 根据domain创建Redis执行器.
     *
     * @param redisDomain the redisDomain
     */
    public RedisExecutor(RedisDomain redisDomain) {

        if (redisDomain != null) {
            this.redisDomain = redisDomain;
        } else {
            this.redisDomain = new RedisDomain();
        }
    }

    /**
     * 查询操作.
     *
     * @param tableDomain key的部分映射
     * @param datakey 查询所需要的数据
     * @param client redisson连接入口
     * @return 返回查询出来的单个数据
     */
    public ResponseData<String> executeQuery(String tableDomain, String datakey,
                                             RedissonClient client) {

        ResponseData<String> result = new ResponseData<String>();
        try {
            if (client == null) {
                return
                        new ResponseData<String>(null, ErrorCode.PERSISTENCE_GET_CONNECTION_ERROR);
            }
            RBucket<String>  rbucket = client.getBucket(tableDomain + VALUE_SPLIT_CHAR + datakey);
            result.setErrorCode(ErrorCode.SUCCESS);
            result.setResult(rbucket.get());
        } catch (Exception e) {
            logger.error("Query data from {{}} with exception", redisDomain.getTableDomain(), e);
            result.setErrorCode(ErrorCode.PERSISTENCE_EXECUTE_FAILED);
        }
        return result;
    }

    /**
     * 增加的执行方法.
     *
     * @param client redisson连接入口
     * @param dataKey Hash(id)
     * @param datas 所需要的数据
     * @return 返回执行成功或失败
     */
    public ResponseData<Integer> execute(RedissonClient client, String dataKey, Object... datas) {

        ResponseData<Integer> result = new ResponseData<Integer>();
        try {
            if (client == null) {
                return
                        new ResponseData<Integer>(null, ErrorCode.PERSISTENCE_GET_CONNECTION_ERROR);
            }
            TransactionArgs transactionArgs = new TransactionArgs();
            DefaultValue value = new DefaultValue();
            if (datas.length == 6) {
                transactionArgs.setRequestId((String) datas[0]);
                transactionArgs.setMethod((String) datas[1]);
                transactionArgs.setArgs((String) datas[2]);
                transactionArgs.setTimeStamp((Long) datas[3]);
                transactionArgs.setExtra((String)datas[4]);
                transactionArgs.setBatch((String)datas[5]);

                String valueString = DataToolUtils.serialize(transactionArgs);
                RBucket<String> rbucket = client.getBucket(
                        redisDomain.getTableDomain() + VALUE_SPLIT_CHAR + dataKey);
                rbucket.set(valueString);
            } else {
                value.setData((String) datas[0]);
                value.setId(dataKey);
                value.setExpire(redisDomain.getExpire());
                if (datas.length == 3) {
                    value.setCreated((Date)datas[1]);
                    value.setUpdated((Date)datas[2]);
                    //datas.lenth==2时为UpDate
                } else if (datas.length == 2) {
                    value.setUpdated((Date)datas[1]);
                }
                String valueString = DataToolUtils.serialize(value);
                RBucket<String> rbucket = client.getBucket(
                        redisDomain.getTableDomain() + VALUE_SPLIT_CHAR + dataKey);
                //解决重复写问题
                if (datas.length == 3 &&  rbucket.get() != null) {
                    return
                            new ResponseData<Integer>(
                                    DataDriverConstant.REDISSON_EXECUTE_FAILED_STATUS,
                                    ErrorCode.PERSISTENCE_EXECUTE_FAILED
                            );
                }
                rbucket.set(valueString);
            }
            result.setErrorCode(ErrorCode.SUCCESS);
            result.setResult(DataDriverConstant.REDISSON_EXECUTE_SUCESS_STATUS);

        } catch (Exception e) {
            logger.error("Update data into {{}} with exception", redisDomain.getBaseDomain(), e);
            result.setErrorCode(ErrorCode.PERSISTENCE_EXECUTE_FAILED);
            result.setResult(DataDriverConstant.REDISSON_EXECUTE_FAILED_STATUS);
        }
        return result;
    }

    /**
     * 删除执行方法.
     *
     * @param dataKey Hash(id)
     * @param client redisson连接入口
     * @return 返回执行成功或失败
     */
    public ResponseData<Integer> executeDelete(String dataKey, RedissonClient client) {

        ResponseData<Integer> result = new ResponseData<Integer>();
        try {
            if (client == null) {
                return
                        new ResponseData<Integer>(null, ErrorCode.PERSISTENCE_GET_CONNECTION_ERROR);
            }
            RBucket<String> rbucket = client.getBucket(
                    redisDomain.getTableDomain() + VALUE_SPLIT_CHAR + dataKey);
            if (rbucket.get() == null) {
                result.setErrorCode(ErrorCode.SUCCESS);
                result.setResult(DataDriverConstant.REDISSON_EXECUTE_FAILED_STATUS);
            } else {
                rbucket.delete();
                result.setErrorCode(ErrorCode.SUCCESS);
                result.setResult(DataDriverConstant.REDISSON_EXECUTE_SUCESS_STATUS);
            }
        } catch (Exception e) {
            logger.error("Delete data into {{}} with exception", redisDomain.getBaseDomain(), e);
            result.setErrorCode(ErrorCode.PERSISTENCE_EXECUTE_FAILED);
            result.setResult(DataDriverConstant.REDISSON_EXECUTE_FAILED_STATUS);
        }
        return result;
    }

    /**
     * 批量新增的语句.
     *
     * @param dataList 占位符所需要的数据
     * @param client redisson连接入口
     * @return 返回受影响的行数
     */
    public ResponseData<Integer> batchAdd(List<List<Object>> dataList, RedissonClient client) {

        ResponseData<Integer> result = new ResponseData<Integer>();
        List<DefaultValue> value = new ArrayList<>();
        try {
            if (client == null) {
                return
                        new ResponseData<Integer>(null, ErrorCode.PERSISTENCE_GET_CONNECTION_ERROR);
            }
            RBatch rbatch = client.createBatch();
            List<Object> values = dataList.get(dataList.size() - 1);
            int size = values.size();
            for (List<Object> list : dataList) {
                if (CollectionUtils.isEmpty(list) || list.size() != size) {
                    return
                            new ResponseData<Integer>(
                                    DataDriverConstant.REDISSON_EXECUTE_FAILED_STATUS,
                                    ErrorCode.PERSISTENCE_BATCH_ADD_DATA_MISMATCH
                            );
                }
            }

            for (int i = 0; i < size; i++) {
                DefaultValue val = new DefaultValue();
                val.setId((String) dataList.get(0).get(i));
                val.setData((String)dataList.get(1).get(i));
                val.setExpire((Date)dataList.get(2).get(i));
                val.setCreated((Date)dataList.get(3).get(i));
                val.setUpdated((Date)dataList.get(4).get(i));
                value.add(val);
            }

            for (DefaultValue val : value) {
                rbatch.getBucket(redisDomain.getTableDomain() + VALUE_SPLIT_CHAR + val.getId())
                        .setAsync(DataToolUtils.serialize(val));
            }
            BatchResult<?> batchResult = rbatch.execute();

            result.setResult(size);
        } catch (RedisException e) {
            logger.error("Batch add data to {{}} with exception", redisDomain.getBaseDomain(), e);
            result.setErrorCode(ErrorCode.PERSISTENCE_EXECUTE_FAILED);
            result.setResult(DataDriverConstant.REDISSON_EXECUTE_FAILED_STATUS);
        }
        return result;
    }
}
