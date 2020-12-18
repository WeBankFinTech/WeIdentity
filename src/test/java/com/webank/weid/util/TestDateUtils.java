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

package com.webank.weid.util;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import org.fisco.bcos.sdk.abi.datatypes.generated.Int256;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * test DateUtils.
 *
 * @author v_wbgyang
 */
public class TestDateUtils {

    private DateFormat df;

    private Date now;

    private SimpleDateFormat simpleDateFormat;

    /**
     * initialization before test.
     */
    @Before
    public void init() {
        TimeZone tz = TimeZone.getTimeZone("Asia/Shanghai");
        df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        df.setTimeZone(tz);

        now = new Date();

        simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    }

    @Test
    public void testGetIso8601Timestamp() {

        String dateString = DateUtils.getTimestamp(now);
        Assert.assertEquals(df.format(now), dateString);

        dateString = DateUtils.getTimestamp(now.getTime());
        Assert.assertEquals(df.format(now), dateString);
    }

    @Test
    public void testConvertStringToDate() throws ParseException {

        String dateString = DateUtils.getTimestamp(now);
        Date date = DateUtils.convertStringToDate(dateString);
        Assert.assertEquals(DateUtils.getTimestamp(date), dateString);

        dateString = DateUtils.getTimestamp(now);
        date = DateUtils.convertLongStringToDate(String.valueOf(now.getTime()));
        Assert.assertEquals(DateUtils.getTimestamp(date), dateString);
    }

    @Test
    public void testConverDateToTimeStamp() throws ParseException {

        String dateString = "2018-12-20 11:35:43";
        long time = DateUtils.converDateToTimeStamp(dateString);
        Assert.assertEquals(simpleDateFormat.parse(dateString).getTime(), time);
    }

    @Test
    public void testIsValidUtcDateString() {

        String dateString = DateUtils.getTimestamp(now);
        boolean isValid = DateUtils.isValidDateString(dateString);
        Assert.assertTrue(isValid);

        isValid = DateUtils.isValidDateString("2018-12-20 11:40:06");
        Assert.assertFalse(isValid);
    }

    @Test
    public void testGetCurrentTimeStampInt256() {

        Int256 int256String = DateUtils.getCurrentTimeStampInt256();
        Assert.assertNotNull(int256String);

        String timeStampString = DateUtils.getCurrentTimeStampString();
        Assert.assertNotNull(timeStampString);

        Long timestamp = DateUtils.getCurrentTimeStamp();
        Assert.assertNotNull(timestamp);
    }

    @Test
    public void testConvertUtcDate() throws Exception {
        String testDate = "2019-03-19T21:12:33Z";
        Long testLongDate = DateUtils.convertUtcDateToTimeStamp(testDate);
        Assert.assertNotNull(testLongDate);
    }
}
