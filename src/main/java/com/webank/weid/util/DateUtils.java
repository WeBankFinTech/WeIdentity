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
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.TimeZone;

import org.fisco.bcos.sdk.abi.datatypes.generated.Int256;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Date formatter utilities.
 *
 * @author lingfenghe
 */
public class DateUtils {

    private static final Logger logger = LoggerFactory.getLogger(DateUtils.class);

    private static String TIME_ZONE = "Asia/Shanghai";

    private static String STRING_DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";

    private static String UTC_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";

    /**
     * Get the ISO8601 timestamp.
     *
     * @param date the date
     * @return the ISO 8601 timestamp
     */
    public static String getTimestamp(Date date) {
        return getDefaultDateFormat().format(date);
    }

    /**
     * Gets the ISO 8601 timestamp.
     *
     * @param date the date
     * @return the ISO 8601 timestamp
     */
    public static String getTimestamp(long date) {
        return getDefaultDateFormat().format(date);
    }

    /**
     * Gets the default date format.
     *
     * @return the default date format
     */
    private static DateFormat getDefaultDateFormat() {
        TimeZone tz = TimeZone.getTimeZone("Asia/Shanghai");
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        df.setTimeZone(tz);
        return df;
    }

    /**
     * Gets the default date format.
     *
     * @return the default date format
     */
    private static DateTimeFormatter getDefaultDateTimeFormatter() {
        DateTimeFormatter ftf = DateTimeFormatter.ofPattern(UTC_DATE_FORMAT);
        return ftf.withZone(ZoneId.of(TIME_ZONE));
    }

    /**
     * Convert a String to Date based on a specific DateFormat.
     *
     * @param dateString the date string
     * @return the date
     * @throws ParseException the parse exception
     */
    public static Date convertStringToDate(String dateString) throws ParseException {
        return getDefaultDateFormat().parse(dateString);
    }

    /**
     * Convert long string to date.
     *
     * @param dateString the date string
     * @return the date
     * @throws ParseException the parse exception
     */
    public static Date convertLongStringToDate(String dateString) throws ParseException {
        return new Date(Long.parseLong(dateString));
    }

    /**
     * Conver date to time stamp.
     *
     * @param time the time in Date
     * @return the long timestamp
     * @throws ParseException the parse exception
     */
    public static long converDateToTimeStamp(String time) throws ParseException {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(STRING_DATE_FORMAT);
        Date date = simpleDateFormat.parse(time);
        long ts = date.getTime();
        return ts;
    }

    /**
     * Conver utc date to time stamp.
     *
     * @param time the time in UTC
     * @return the long timestamp
     * @throws ParseException the parse exception
     */
    public static Long convertUtcDateToTimeStamp(String time) throws ParseException {
        DateFormat simpleDateFormat = getDefaultDateFormat();
        Date date = simpleDateFormat.parse(time);
        return date.getTime();
    }

    /**
     * Conver utc date to without millisecond timestamp.
     *
     * @param time the time in UTC
     * @return the long timestamp
     */
    public static Long convertUtcDateToNoMillisecondTime(String time) {
        DateTimeFormatter dtf = getDefaultDateTimeFormatter();
        LocalDateTime date = LocalDateTime.parse(time, dtf);
        return date.toInstant(ZoneOffset.of("+8")).getEpochSecond();
    }

    /**
     * Check the UTC format validity of a Date String.
     *
     * @param dateString the date string
     * @return true, if is valid UTC date string
     */
    public static boolean isValidDateString(String dateString) {
        try {
            DateFormat df = getDefaultDateFormat();
            df.setLenient(false);
            df.parse(dateString);
            return true;
        } catch (ParseException parseEx) {
            return false;
        }
    }

    /**
     * Check the timestamp date to UTC date string.
     *
     * @param date the timestamp string
     * @return UTC formatted date string
     */
    public static String convertTimestampToUtc(Long date) {
        DateFormat df = getDefaultDateFormat();
        df.setLenient(false);
        return df.format(new Date(date));
    }

    /**
     * Convert the timestamp without millisecond date to UTC date string.
     *
     * @param date the timestamp without millisecond string
     * @return UTC formatted date string
     */
    public static String convertNoMillisecondTimestampToUtc(Long date) {
        if (String.valueOf(date) != null
            && String.valueOf(date).length() == getNoMillisecondTimeStampString().length()) {
            DateTimeFormatter dtf = getDefaultDateTimeFormatter();
            return dtf.format(LocalDateTime.ofInstant(
                Instant.ofEpochSecond(date),
                ZoneId.of(TIME_ZONE)));
        } else {
            logger.error("the timestamp is illegal.");
            return null;
        }
    }

    /**
     * Get current timestamp in Int256 type.
     *
     * @return the current time stamp int 256
     */
    public static Int256 getCurrentTimeStampInt256() {
        return new Int256(System.currentTimeMillis());
    }

    /**
     * Get current no-ms timestamp in Int256 type.
     *
     * @return the current time stamp int 256
     */
    public static Int256 getNoMillisecondTimeStampInt256() {
        return new Int256(DateUtils.getNoMillisecondTimeStamp());
    }

    /**
     * Get current timestamp in String type.
     *
     * @return the current time stamp string
     */
    public static String getCurrentTimeStampString() {
        return String.valueOf(System.currentTimeMillis());
    }

    /**
     * Get current timestamp in long type.
     *
     * @return the current time stamp long
     */
    public static Long getCurrentTimeStamp() {
        return System.currentTimeMillis();
    }

    /**
     * Get current timestamp without millisecond in long type.
     *
     * @return the current time stamp without millisecond long
     */
    public static Long getNoMillisecondTimeStamp() {
        return Instant.now().getEpochSecond();
    }

    /**
     * Get current timestamp without millisecond in String type.
     *
     * @return the current time stamp without millisecond String
     */
    public static String getNoMillisecondTimeStampString() {
        return String.valueOf(Instant.now().getEpochSecond());
    }

    /**
     * compare with the long date with CurrentTime.
     *
     * @param date long date
     * @return boolean
     */
    public static boolean isAfterCurrentTime(Long date) {
        if (String.valueOf(date) != null
            && String.valueOf(date).length() == getCurrentTimeStampString().length()) {
            return date > getCurrentTimeStamp();
        } else if (String.valueOf(date) != null
            && String.valueOf(date).length() == getNoMillisecondTimeStampString().length()) {
            return date > getNoMillisecondTimeStamp();
        } else {
            return false;
        }
    }

    /**
     * convert timeStamp which contain millisecond to without millisecond timeStamp.
     *
     * @param date timeStamp
     * @return the timeStamp without millisecond
     */
    public static Long convertToNoMillisecondTimeStamp(Long date) {
        if (String.valueOf(date) == null) {
            logger.error("the timestamp is null.");
            return null;
        }
        if (String.valueOf(date) != null
            && String.valueOf(date).length() != getCurrentTimeStampString().length()) {
            if (String.valueOf(date).length() == getNoMillisecondTimeStampString().length()) {
                return date;
            }
            logger.error("the timestamp is illegal.");
            return null;
        }
        DateTimeFormatter ftf = DateTimeFormatter.ofPattern(STRING_DATE_FORMAT);
        String time = ftf.format(
            LocalDateTime.ofInstant(Instant.ofEpochMilli(date),
                ZoneId.of(TIME_ZONE)));
        LocalDateTime parse = LocalDateTime.parse(time, ftf);
        return LocalDateTime.from(parse).atZone(ZoneId.of(TIME_ZONE)).toInstant().getEpochSecond();
    }
}
