/*
 *       Copyright© (2019) WeBank Co., Ltd.
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

package com.webank.weid.suite.endpoint;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.protocol.base.EndpointInfo;
import com.webank.weid.util.DataToolUtils;
import com.webank.weid.util.PropertyUtils;

/**
 * Handle registered Endpoint data related functionality.
 *
 * @author chaoxinhu 2019.8
 */
public class EndpointDataUtil {

    private static final Logger logger = LoggerFactory.getLogger(EndpointDataUtil.class);

    /**
     * Properties object and keep-maint endpoint info.
     */
    private static Properties props;
    private static List<EndpointInfo> endpointInfoList;

    /**
     * configuration file.
     */
    private static final String CENTRAL_DATA = "endpoint-data.properties";

    static {
        loadAllEndpointInfoFromProps();
    }

    /**
     * Clear all properties.
     */
    public static void clearProps() {
        props = new Properties();
        endpointInfoList = new ArrayList<>();
    }

    /**
     * load configuration file.
     */
    private static synchronized void loadPropsFromFile() {
        props = new Properties();
        try {
            InputStream input = EndpointDataUtil.class
                .getClassLoader().getResourceAsStream(CENTRAL_DATA);
            props.load(input);
            logger.info("loadPropsFromFile finish...");
        } catch (Exception e) {
            logger.error("loadPropsFromFile error", e);
        }
    }

    /**
     * Store the value in the property file.
     *
     * @throws Exception when File does not exist
     */
    public static synchronized void saveEndpointsToFile() throws Exception {
        String path = EndpointDataUtil.class
            .getClassLoader().getResource(CENTRAL_DATA).getPath();
        File file = new File(path);
        props = new Properties();
        int index = 1;
        for (EndpointInfo endpointInfo : endpointInfoList) {
            props.setProperty("ep." + index + ".name", endpointInfo.getRequestName());
            props.setProperty("ep." + index + ".in", stringListToString(endpointInfo.getInAddr()));
            props.setProperty("ep." + index + ".desc", endpointInfo.getDescription());
            index++;
        }
        props.store(new FileOutputStream(file), null);
    }

    /**
     * Wrapper class, load all endpoint info from in-mem props into Endpoint list.
     */
    public static void loadAllEndpointInfoFromProps() {
        loadPropsFromFile();
        List<EndpointInfo> allEndpoints = new ArrayList<>();
        Map<Integer, EndpointInfo> endpointMap = new ConcurrentHashMap<>();
        try {
            Properties tempProps = new Properties(props);
            Set<String> keys = tempProps.stringPropertyNames();
            for (String key : keys) {
                int index = Integer.valueOf(StringUtils.splitByWholeSeparator(key, ".")[1]);
                if (endpointMap.containsKey(index)) {
                    EndpointInfo endpointInfo = endpointMap.get(index);
                    endpointMap.put(index, fillInEndpointInfo(endpointInfo, key, tempProps));
                } else {
                    EndpointInfo endpointInfo = new EndpointInfo();
                    endpointInfo = fillInEndpointInfo(endpointInfo, key, tempProps);
                    if (!isEndpointInfoEmpty(endpointInfo)) {
                        endpointMap.put(index, endpointInfo);
                    }
                }
            }
        } catch (Exception e) {
            logger.error("load endpoint info error", e);
        }
        for (Map.Entry<Integer, EndpointInfo> pair : endpointMap.entrySet()) {
            EndpointInfo endpointInfo = pair.getValue();
            // Merge all duplicate records' inAddr (match their requestName)
            for (EndpointInfo storedInfo : allEndpoints) {
                if (storedInfo.getRequestName().equalsIgnoreCase(endpointInfo.getRequestName())) {
                    allEndpoints.remove(storedInfo);
                    List<String> newList = new ArrayList<>(endpointInfo.getInAddr());
                    newList.addAll(storedInfo.getInAddr());
                    endpointInfo.setInAddr(newList);
                    endpointInfo.setDescription(storedInfo.getDescription());
                }
            }
            allEndpoints.add(endpointInfo);
        }
        endpointInfoList = allEndpoints;
    }

    private static boolean isEndpointInfoEmpty(EndpointInfo endpointInfo) {
        return (StringUtils.isEmpty(endpointInfo.getRequestName()) && StringUtils
            .isEmpty(endpointInfo.getDescription())
            && (endpointInfo.getInAddr() == null || endpointInfo.getInAddr().size() == 0));
    }

    /**
     * Fetch each entry one by one into the in-memory endpoint table.
     */
    private static EndpointInfo fillInEndpointInfo(EndpointInfo endpointInfo, String key,
        Properties props) {
        if (StringUtils.splitByWholeSeparator(key, ".")[2].equalsIgnoreCase("name")) {
            endpointInfo.setRequestName(props.getProperty(key));
        } else if (StringUtils.splitByWholeSeparator(key, ".")[2].equalsIgnoreCase("in")) {
            List<String> oldList = endpointInfo.getInAddr();
            if (oldList == null) {
                oldList = new ArrayList<>();
            }
            oldList.addAll(stringToStringList(props.getProperty(key)));
            endpointInfo.setInAddr(oldList);
        } else if (StringUtils.splitByWholeSeparator(key, ".")[2].equalsIgnoreCase("desc")) {
            endpointInfo.setDescription(props.getProperty(key));
        } else {
            logger.error("Incorrect endpoint info entry: ", key, props.getProperty(key));
            System.out.println("Incorrect endpoint info entry: " + key + props.getProperty(key));
        }
        return endpointInfo;
    }

    /**
     * Convert a comma separated String to List.
     *
     * @param str input string
     * @return list
     */
    public static List<String> stringToStringList(String str) {
        return new ArrayList<>(Arrays.asList(str.split(",")));
    }

    /**
     * Convert a string List to a comma separated string.
     *
     * @param stringList input list
     * @return string
     */
    public static String stringListToString(List<String> stringList) {
        return StringUtils.join(stringList, ",");
    }

    /**
     * Get all endpoint info.
     *
     * @return endpoint info list
     */
    public static List<EndpointInfo> getAllEndpointInfo() {
        return endpointInfoList;
    }

    /**
     * Wrapper class, remove an endpoint info from props from properties file. Finer granular
     * removal.
     *
     * @param endpointInfo the input endpoint info
     * @return true if succeeded, false otherwise
     */
    public static boolean removeEndpoint(EndpointInfo endpointInfo) {
        List<EndpointInfo> localList = new ArrayList<>(endpointInfoList);
        List<EndpointInfo> allInfoList = new ArrayList<>(localList);
        for (EndpointInfo infoItem : allInfoList) {
            if (endpointInfo.getRequestName().equalsIgnoreCase(infoItem.getRequestName())) {
                localList.remove(infoItem);
            }
        }
        endpointInfoList = localList;
        try {
            saveEndpointsToFile();
            return true;
        } catch (Exception e) {
            logger.error("remove Endpoint has error.", e);
            return false;
        }
    }

    /**
     * Merge current local endpoint info list to central.
     *
     * @param endpointInfo the endpoint info
     */
    public static synchronized void mergeToCentral(EndpointInfo endpointInfo) {
        List<String> inAddr = endpointInfo.getInAddr();
        if (inAddr != null && inAddr.size() > 1) {
            // Remove potential duplicates in addr list
            Set<String> set = new HashSet<>(endpointInfo.getInAddr());
            inAddr.clear();
            inAddr.addAll(set);
            endpointInfo.setInAddr(inAddr);
        }
        if (endpointInfoList.size() == 0) {
            endpointInfoList.add(endpointInfo);
            return;
        }
        List<EndpointInfo> tempList = new ArrayList<>(endpointInfoList);
        List<EndpointInfo> finalList = new ArrayList<>();
        boolean exists = false;
        for (EndpointInfo localInfo : tempList) {
            if (localInfo.getRequestName().equalsIgnoreCase(endpointInfo.getRequestName())) {
                List<String> inAddrList = localInfo.getInAddr();
                inAddrList.addAll(endpointInfo.getInAddr());
                Set<String> inSet = new HashSet<>(inAddrList);
                inAddrList.clear();
                inAddrList.addAll(inSet);
                localInfo.setInAddr(inAddrList);
                exists = true;
            }
            finalList.add(localInfo);
            logger.debug("Merged Endpoint: " + DataToolUtils.serialize(localInfo));
            System.out.println("Merged Endpoint: " + DataToolUtils.serialize(localInfo));
        }
        if (!exists) {
            finalList.add(endpointInfo);
            logger.debug("Merged Endpoint: " + DataToolUtils.serialize(endpointInfo));
            System.out.println("Merged Endpoint: " + DataToolUtils.serialize(endpointInfo));
        }
        endpointInfoList = finalList;
    }
}
