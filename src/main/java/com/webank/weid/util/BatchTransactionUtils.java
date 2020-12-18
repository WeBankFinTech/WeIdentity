package com.webank.weid.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.DataDriverConstant;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.ParamKeyConstant;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.request.TransactionArgs;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.suite.api.persistence.PersistenceFactory;
import com.webank.weid.suite.api.persistence.inf.Persistence;
import com.webank.weid.suite.api.persistence.params.PersistenceType;

/**
 * 批量交易处理类.
 *
 * @author tonychen 2020年4月1日
 */
public class BatchTransactionUtils {

    private static final Logger logger = LoggerFactory.getLogger(BatchTransactionUtils.class);

    /**
     * 阈值，当写入的交易达到这个条数时，换新文件.
     */
    private static final Integer THRESHOLD = 10000;
    private static OutputStreamWriter ow = null;
    private static String secretKey;
    private static String currentFilePath;

    /**
     * 本机IP地址.
     */
    private static String ipAddr;
    private static Integer count;
    private static String currentDir = System.getProperty("user.dir");
    private static boolean isSaveToDb = true;

    /**
     * persistence.
     */
    private static Persistence dataDriver;
    private static PersistenceType persistenceType;
    private static Integer index = 0;
    private static String currentDay;

    static {
        Date date = new Date();
        currentDay = new SimpleDateFormat("yyyyMMdd").format(date);
    }

    /**
     * 获取本机IP.
     *
     * @return 本机IP地址
     */
    private static String getIp() {

        if (!StringUtils.isBlank(ipAddr)) {
            return ipAddr;
        }
        InetAddress address = null;
        try {
            address = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            logger.error("[getIp] get local ip failed. Error message:{}", e);
            return null;
        }
        ipAddr = address.getHostAddress();
        return ipAddr;
    }

    private static Persistence getDataDriver() {
        String type = PropertyUtils.getProperty("persistence_type");
        if (type.equals("mysql")) {
            persistenceType = PersistenceType.Mysql;
        } else if (type.equals("redis")) {
            persistenceType = PersistenceType.Redis;
        }
        if (dataDriver == null) {
            dataDriver = PersistenceFactory.build(persistenceType);
        }
        return dataDriver;
    }

    /**
     * 获取用来加密私钥的对称秘钥.
     *
     * @return 对称秘钥
     */
    private static String getKey() {

        if (!StringUtils.isBlank(secretKey)) {
            return secretKey;
        } else {
            ResponseData<String> dbResp = getDataDriver().get(DataDriverConstant.DOMAIN_ENCRYPTKEY,
                PropertyUtils.getProperty("blockchain.orgid"));
            Integer errorCode = dbResp.getErrorCode();
            if (errorCode != ErrorCode.SUCCESS.getCode()) {
                logger
                    .error("[writeTransaction] save encrypt private key to db failed.errorcode:{}",
                        errorCode);
                return null;
            }
            secretKey = dbResp.getResult();
            return secretKey;
        }
    }

    /**
     * 记录交易记录，后续采用离线批处理的方式写入区块链.
     *
     * @param requestId 对应本次交易的id
     * @param method 交易方法
     * @param args 交易参数
     * @param extra 额外信息
     * @return 如果成功，返回true，否则flase
     */
    public static boolean writeTransaction(
        String requestId,
        String method,
        String[] args,
        String extra) {

        String parameters = processArgs(args);
        if (parameters == null) {
            logger.error("[writeTransaction] parameters is illegal. requestId:{},method:{}",
                requestId,
                method);
            return false;
        }
        long timeStamp = System.currentTimeMillis();
        if (isSaveToDb) {
            TransactionArgs transactionArgs = new TransactionArgs();
            transactionArgs.setArgs(parameters);
            transactionArgs.setBatch(getCurrentDay());
            transactionArgs.setExtra(extra);
            transactionArgs.setMethod(method);
            transactionArgs.setRequestId(requestId);
            transactionArgs.setTimeStamp(timeStamp);
            return saveToDb(transactionArgs);
        }

        String content = new StringBuffer()
            .append(requestId)
            .append(WeIdConstant.PIPELINE)
            .append(method)
            .append(WeIdConstant.PIPELINE)
            .append(parameters)
            .append(WeIdConstant.PIPELINE)
            .append(extra)
            .append(WeIdConstant.PIPELINE)
            .append(timeStamp).toString();

        String filePath = getFilePath();
        return saveToLogFile(content, filePath);
    }

    private static String getCurrentDay() {

        Date date = new Date();
        String currentDate = new SimpleDateFormat("yyyyMMdd").format(date);
        return currentDate;
    }

    /**
     * 交易保存至数据库.
     *
     * @return 状态
     */
    private static boolean saveToDb(TransactionArgs transaction) {

        ResponseData<Integer> dbResp = getDataDriver().addTransaction(transaction);
        if (dbResp.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
            return false;
        }
        return true;
    }

    private static String getFilePath() {

        String currentDate = getCurrentDay();
        if (!StringUtils.equals(currentDay, currentDate)) {
            index = 0;
            count = 0;
        }
        String filePath =
            currentDir + File.separator + currentDate + File.separator + getIp() + "_binlog_"
                + index;
        if (StringUtils.equals(currentFilePath, filePath)) {
            count++;
            //如果记录条数超过阈值，要换文件
            if (count >= THRESHOLD) {
                index++;
            }
        } else {
            currentFilePath = filePath;
            count = 1;
        }
        return filePath;
    }

    private static String processArgs(String[] args) {

        if (args == null || args.length == 0) {

            return null;
        }
        int length = args.length;
        StringBuffer content = new StringBuffer();
        for (int i = 0; i < length - 2; i++) {

            content.append(args[i]).append(",");
        }
        String privateKey = args[length - 2];
        WeIdPrivateKey weIdPrivateKey = new WeIdPrivateKey(privateKey);
        String weId = WeIdUtils.getWeIdFromPrivateKey(weIdPrivateKey);

        //将私钥进行对称加密后存到数据库里
        //String encryptKey = CryptServiceFactory.getCryptService(CryptType.AES)
        //    .encrypt(privateKey, getKey());
        //ResponseData<Integer> dbResp = getDataDriver()
        //    .addOrUpdate(DataDriverConstant.DOMAIN_ENCRYPTKEY, weId, encryptKey);
        //Integer errorCode = dbResp.getErrorCode();
        //if (errorCode != ErrorCode.SUCCESS.getCode()) {
        //    logger.error("[writeTransaction] save encrypt private key to db failed.errorcode:{}",
        //        errorCode);
        //    return null;
        //}

        content.append(weId).append(",");
        content.append(args[length - 1]);
        return content.toString();
    }

    /**
     * 将交易信息写入binlog.
     *
     * @param content 要写入的内容
     * @param fileName 文件名
     */
    private static boolean saveToLogFile(
        String content,
        String fileName) {

        File f = new File(fileName);
        File parent = f.getParentFile();
        if (!parent.exists()) {
            parent.mkdirs();
        }
        if (!f.exists()) {
            try {
                f.createNewFile();
            } catch (IOException e) {
                logger.error("[writeToLogFile] create file failed. filePath:{}, error:{}", fileName,
                    e);
                return false;
            }
        }
        try {
            ow = new OutputStreamWriter(new FileOutputStream(fileName, true),
                ParamKeyConstant.UTF_8);
            ow.write(content);
            ow.close();
            return true;
        } catch (IOException e) {
            logger.error("writer file exception.", e);
        } finally {
            if (null != ow) {
                try {
                    ow.close();
                } catch (IOException e) {
                    logger.error("io close exception.", e);
                    return false;
                }
            }
        }
        return true;
    }
}
