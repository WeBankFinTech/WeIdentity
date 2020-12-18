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

package com.webank.weid.suite.persistence;

import java.util.Date;

import lombok.Data;

@Data
public class DefaultValue {

    /**
     * 主键.
     */
    private String id;

    /**
     * blob主体数据.
     */
    private String data;

    /**
     * 创建时间.
     */
    private Date created;
    /**
     * 更新时间.
     */
    private Date updated;

    /**
     * 编码格式.
     */
    private String protocol;

    /**
     * 超时时间.
     */
    private Date expire;

    /**
     * 数据所属版本.
     */
    private String version;

    /**
     * 扩展字段1.
     */
    private int ext1;

    /**
     * 扩展字段2.
     */
    private int ext2;

    /**
     * 扩展字段3.
     */
    private String ext3;

    /**
     * 扩展字段4.
     */
    private String ext4;

}
