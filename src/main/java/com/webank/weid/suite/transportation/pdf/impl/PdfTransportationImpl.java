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

package com.webank.weid.suite.transportation.pdf.impl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.fontbox.ttf.TTFParser;
import org.apache.fontbox.ttf.TrueTypeFont;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.fisco.bcos.sdk.utils.Numeric;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.CredentialConstant;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.exception.WeIdBaseException;
import com.webank.weid.protocol.base.Cpt;
import com.webank.weid.protocol.base.CredentialPojo;
import com.webank.weid.protocol.base.CredentialPojoList;
import com.webank.weid.protocol.base.PresentationE;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.inf.JsonSerializer;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.rpc.CptService;
import com.webank.weid.service.impl.CptServiceImpl;
import com.webank.weid.suite.api.transportation.inf.PdfTransportation;
import com.webank.weid.suite.api.transportation.params.EncodeType;
import com.webank.weid.suite.api.transportation.params.ProtocolProperty;
import com.webank.weid.suite.encode.EncodeProcessorFactory;
import com.webank.weid.suite.entity.EncodeData;
import com.webank.weid.suite.entity.PdfVersion;
import com.webank.weid.suite.transportation.AbstractPdfTransportation;
import com.webank.weid.suite.transportation.pdf.protocol.PdfAttributeInfo;
import com.webank.weid.util.DataToolUtils;

/**
 * pdf模式序列化接口实现.
 * @author yanggang
 *
 */
public class PdfTransportationImpl
    extends AbstractPdfTransportation
    implements PdfTransportation {

    private static final Logger logger = LoggerFactory.getLogger(PdfTransportationImpl.class);

    private static final PdfVersion version = PdfVersion.V1;

    private static final float MARGIN = 408;

    private static final float POS_CONTENT_X = 100;

    private static final float POS_CONTENT_Y = 700;

    private static final float BOTTOM = 50;

    private static final float POS_TITLE_X = 260;

    private static final float POS_TITLE_Y = 750;

    private static final int FONT_SIZE_TITLE = 18;

    private static final int FONT_SIZE_CONTENT = 12;

    private static final String PDF_SUFFIX = ".pdf";

    private static final String PATH_LINKER = "/";

    private static final String FILE_SEPARATOR = ".";

    private static final String PDF_ATTRIBUTE_ID = "id";
    private static final String PDF_ATTRIBUTE_AMOP_ID = "amopId";
    private static final String PDF_ATTRIBUTE_DATA = "data";
    private static final String PDF_ATTRIBUTE_ENCODE_TYPE = "encodeType";
    private static final String PDF_ATTRIBUTE_VERSION = "version";
    private static final String PDF_ATTRIBUTE_TEMPLATE_ID = "pdfTemplateId";

    private static CptService cptService = new CptServiceImpl();

    /**
     * 根据Claim和Salt把需要显示的数据写入到disclosureInfo中.
     *
     * @param disclosureInfo credentialList包含元素个数
     * @param salt 当前credential对应的盐值
     * @param claim 当前credential对应的claim
     * @param prefix 递归时用于处理字符串的前缀
     * @param propMap CPT的properties值，用于获取CPT中name字段
     * @param isSpecTpl 是否是指定pdf模板情况
     */
    private void buildDisclosureInfo(
        LinkedHashMap<String, String> disclosureInfo,
        Map<String, Object> salt,
        Map<String, Object> claim,
        StringBuilder prefix,
        Map<String, Object> propMap,
        Boolean isSpecTpl) throws WeIdBaseException {

        if (salt == null) {
            logger.error("buildDisclosureInfo due to salt illegal error.");
            throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
        }

        for (Map.Entry<String, Object> entry : salt.entrySet()) {
            Object saltV = entry.getValue();

            //获取与盐值的key对应的claim的value
            Object claimV;
            if (claim.containsKey(entry.getKey())) {
                claimV = claim.get(entry.getKey());
            } else {
                logger.error("buildDisclosureInfo due to claimV illegal error.");
                throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
            }

            //propMapv为cpt中的properties信息，用于设置默认模板显示name值
            Map<String, Object> propMapV = new HashMap<>(3);

            //如果当前cpt为简单单级cpt不包含properties字段，由下面判断name来获取prefix
            if (!propMap.isEmpty()) {
                try {
                    propMapV = DataToolUtils.objToMap(propMap.get(entry.getKey()));
                } catch (Exception e) {
                    logger.error("buildDisclosureInfo due to propMap cast to propMapV error.", e);
                    throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
                }
            }

            //1. 如果claim为多层Map则递归解析数据
            if (saltV instanceof Map) {
                //判断name是否存在
                if (propMapV != null) {
                    if (isSpecTpl
                        || !propMapV.containsKey("name")
                        || String.valueOf(propMapV.get("name")).equals("")) {
                        prefix.append(entry.getKey());
                    } else {
                        prefix.append(propMapV.get("name"));
                    }
                } else {
                    logger.error(
                        "buildDisclosureInfo duo to "
                            + "map type cpt missing properties, propMapV is null error.");
                    throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
                }
                prefix.append("-");
                Map<String, Object> certProp = null;
                try {
                    if (propMapV.containsKey("properties")) {
                        certProp = DataToolUtils.objToMap(propMapV.get("properties"));
                    }
                } catch (Exception e) {
                    logger.error("buildDisclosureInfo duo to objToMap propMapV error.", e);
                    throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
                }

                //递归处理多层Map
                buildDisclosureInfo(
                    disclosureInfo,
                    (HashMap) saltV,
                    (HashMap) claimV,
                    prefix,
                    certProp,
                    isSpecTpl
                );
                stringTools(prefix);

                //2. 如果claim为List则根据List内部结构来处理
            } else if (saltV instanceof List) {
                Map<String, Object> items;
                Map<String, Object> itemsProp;
                try {
                    items = DataToolUtils.objToMap(propMapV.get("items"));
                    itemsProp = DataToolUtils.objToMap(items.get("properties"));
                } catch (Exception e) {
                    logger.error("buildDisclosureInfo due to objToMap items error.", e);
                    throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
                }

                int i = 0;
                //判断name是否存在
                if (isSpecTpl
                    || !propMapV.containsKey("name")
                    || String.valueOf(propMapV.get("name")).equals("")) {
                    prefix.insert(0, entry.getKey());
                } else {
                    prefix.insert(0, propMapV.get("name"));
                }
                prefix.append("[").append(i++).append("]").append("-");

                //处理List结构的claim
                buildDisclosureInfoByList(
                    disclosureInfo,
                    (ArrayList<Object>) saltV,
                    (ArrayList<Object>) claimV,
                    prefix,
                    itemsProp,
                    isSpecTpl
                );

                //3. 如果claim为单层Map则直接处理
            } else {
                //盐值为0，说明是非披露字段
                if (entry.getValue().equals("0")) {
                    continue;
                }

                //判断name是否存在
                try {
                    if (isSpecTpl
                        || !propMapV.containsKey("name")
                        || String.valueOf(propMapV.get("name")).equals("")) {
                        disclosureInfo.put(prefix + entry.getKey(), String.valueOf(claimV));
                    } else {
                        disclosureInfo.put(
                            prefix + String.valueOf(propMapV.get("name")),
                            String.valueOf(claimV));
                    }
                } catch (WeIdBaseException e) {
                    logger.error("buildDisclosureInfo due to get name error.", e);
                    throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
                }
            }
        }
    }

    /**
     * 对要写入disclosureInfo中字符串进行处理.
     *
     * @param prefix 字符串前缀
     */
    private void stringTools(StringBuilder prefix) {

        boolean second = false;
        byte dotNum = 0;
        //如果包含多个"-" ，则删除倒数第二个点后面的内容；如果只有一个"-"则置为空
        for (int i = prefix.length() - 1; i > 0; i--) {
            if (prefix.charAt(i) == '-') {
                dotNum++;
                if (second) {
                    prefix.replace(0, prefix.length(), prefix.substring(0, i + 1));
                    break;
                }
                second = true;
            }
        }
        if (dotNum == 1) {
            prefix.delete(0, prefix.length());
        }
    }

    /**
     * 处理List类型的Claim.
     *
     * @param disclosureInfo credentialList包含元素个数
     * @param salt 当前credential对应的盐值
     * @param claim 当前credential对应的claim
     * @param prefix 递归时用于处理字符串的前缀
     * @param items CPT中List类型获取Properties
     */
    private void buildDisclosureInfoByList(
        LinkedHashMap<String, String> disclosureInfo,
        List<Object> salt,
        List<Object> claim,
        StringBuilder prefix,
        Map<String, Object> items,
        Boolean isSpecTpl) throws WeIdBaseException {

        try {
            //传入的salt就是List，需要遍历每一个salt[i]
            for (int i = 0; i < salt.size(); i++) {
                Object claimObj = claim.get(i);
                Object saltObj = salt.get(i);

                if (saltObj instanceof Map) {
                    //List里面是Map
                    buildDisclosureInfo(
                        disclosureInfo,
                        (HashMap) saltObj,
                        (HashMap) claimObj,
                        prefix,
                        items,
                        isSpecTpl);
                } else if (saltObj instanceof List) {
                    //List里面是List,就一直递归直到是Map
                    buildDisclosureInfoByList(
                        disclosureInfo,
                        (ArrayList<Object>) saltObj,
                        (ArrayList<Object>) claimObj,
                        prefix,
                        items,
                        isSpecTpl);
                }
                prefix.replace(0, prefix.length(), prefix.substring(0, prefix.length() - 3));
                prefix.append(i + 1).append("]").append("-");
            }
            stringTools(prefix);
        } catch (Exception e) {
            logger.error("buildDisclosureInfoByList error.", e);
            throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
        }
    }

    /**
     * 获取字符串在PDF中占用长度.
     *
     * @param str 需要计算的字符串
     * @param fontSize 字体大小
     * @param font 具体字体
     * @return 字符串占用长度
     */
    private float calcStrLength(String str, int fontSize, PDFont font) throws WeIdBaseException {

        float len;
        try {
            len = fontSize * font.getStringWidth(str) / 1000;
        } catch (Exception e) {
            logger.error("calcStrLength error.", e);
            throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
        }
        return len;
    }

    /**
     * 处理单条disclosureInfo数据过长需要分行显示问题.
     *  @param output 需要处理的字符串
     * @param fontSize 字体大小
     * @param font 具体字体
     * @param lines 处理后存储结果的ArrayList
     */
    private void buildLines(
        String output,
        int fontSize,
        PDFont font,
        ArrayList<String> lines) throws WeIdBaseException {

        try {
            String str;
            int startPos = 0;
            for (int i = 0; i < output.length(); i++) {
                str = output.substring(startPos, i);
                if (calcStrLength(str, fontSize, font) > MARGIN) {
                    lines.add(str);
                    startPos = i;
                }
            }
            str = output.substring(startPos);
            lines.add(str);
        } catch (Exception e) {
            logger.error("buildLines error.", e);
            throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
        }
    }

    /**
     * 把处理好的多行数据lines写入到PDF中.
     *
     * @param lineSize line元素个数
     * @param contents 当前PDF页面
     * @param fontSize 字体大小
     * @param font 具体字体
     * @param pos 写入位置
     * @param lines 存有多行字符串的ArrayList
     */
    private void addMultiLine2Pdf(
        int lineSize,
        PDPageContentStream contents,
        int fontSize,
        PDFont font,
        float pos,
        ArrayList<String> lines) {

        String text;
        for (int j = 0; j < lineSize; j++) {
            text = lines.get(j);
            addContent(contents, text, POS_CONTENT_X, pos, font, fontSize);
            pos = pos - 15;
        }
    }

    private void addContent(
        PDPageContentStream contents,
        String text,
        float posX,
        float posY,
        PDFont font,
        int fontSize) {

        try {
            contents.beginText();
            contents.setFont(font, fontSize);
            contents.newLineAtOffset(posX, posY);
            contents.showText(text);
            contents.endText();
        } catch (Exception e) {
            logger.error("addContent error.", e);
            throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
        }
    }

    /**
     * 为PDF添加属性信息.
     *  @param document 当前PDF
     * @param pdfAttributeInfo PDF协议数据
     */
    private void addAttributeInfo(PDDocument document, PdfAttributeInfo pdfAttributeInfo) {

        PDDocumentInformation pdd = document.getDocumentInformation();
        pdd.setCustomMetadataValue(PDF_ATTRIBUTE_ID, pdfAttributeInfo.getId());
        pdd.setCustomMetadataValue(PDF_ATTRIBUTE_AMOP_ID, pdfAttributeInfo.getAmopId());
        pdd.setCustomMetadataValue(PDF_ATTRIBUTE_DATA, String.valueOf(pdfAttributeInfo.getData()));
        pdd.setCustomMetadataValue(
            PDF_ATTRIBUTE_ENCODE_TYPE, String.valueOf(pdfAttributeInfo.getEncodeType()));
        pdd.setCustomMetadataValue(
            PDF_ATTRIBUTE_VERSION, String.valueOf(pdfAttributeInfo.getVersion()));
        pdd.setCustomMetadataValue(
            PDF_ATTRIBUTE_TEMPLATE_ID, String.valueOf(pdfAttributeInfo.getTemplateId()));
    }

    /**
     * 将PDF中的属性信息解析到PdfBaseData数据结构中.
     *
     * @param pdd PDF属性信息
     * @param pdfAttributeInfo PDF协议数据
     */
    private void buildPdfDataFromPdf(PDDocumentInformation pdd, PdfAttributeInfo pdfAttributeInfo) {

        pdfAttributeInfo.setId(pdd.getCustomMetadataValue(PDF_ATTRIBUTE_ID));
        pdfAttributeInfo.setAmopId(pdd.getCustomMetadataValue(PDF_ATTRIBUTE_AMOP_ID));
        pdfAttributeInfo.setData(pdd.getCustomMetadataValue(PDF_ATTRIBUTE_DATA));
        pdfAttributeInfo.setEncodeType(
            Integer.parseInt(pdd.getCustomMetadataValue(PDF_ATTRIBUTE_ENCODE_TYPE)));
        pdfAttributeInfo.setVersion(
            Integer.parseInt(pdd.getCustomMetadataValue(PDF_ATTRIBUTE_VERSION)));
        pdfAttributeInfo.setTemplateId(pdd.getCustomMetadataValue(PDF_ATTRIBUTE_TEMPLATE_ID));
    }

    /**
     * 把presentation数据写入默认PDF模板，输出PDF流.
     *
     * @param <T> JsonSerializer
     * @param object serialize函数输入的object
     * @param pdfAttributeInfo PDF协议数据
     * @return PDF流数据
     * @throws WeIdBaseException exception
     */
    private <T extends JsonSerializer>  byte[] buildPdf4DefaultTpl(
        T object,
        PdfAttributeInfo pdfAttributeInfo) throws WeIdBaseException {

        try {
            PresentationE presentation;
            CredentialPojo credentialPojo;
            List<CredentialPojo> credentialPojoList = new ArrayList<>(3);
            List<CredentialPojo> creList = new ArrayList<>(1);

            //获取credentialPojoList
            if (object instanceof PresentationE) {
                presentation = (PresentationE) object;

                //处理credentialList不存在的情况
                if (presentation.getVerifiableCredential().size() == 0) {
                    logger.error(
                        "buildPdf4SpecTpl due to credentialList size equal to zero error.");
                    throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
                }

                //presentationE不存在多签情况，直接获取credentialList
                credentialPojoList = presentation.getVerifiableCredential();
            } else if (object instanceof CredentialPojo) {
                credentialPojo = (CredentialPojo) object;

                //多签情况递归获取最内层credentialList，否则直接获取credentialList
                if (
                    credentialPojo.getClaim().containsKey("credentialList")
                    && credentialPojo.getClaim().size() == 1) {
                    getMultiSignClaim(credentialPojo, creList);
                    credentialPojoList = creList;
                } else {
                    credentialPojoList.add(credentialPojo);
                }
            } else if (object instanceof CredentialPojoList) {
                credentialPojoList = (CredentialPojoList) object;
            } else {
                logger.error(
                    "buildPdf4DefaultTpl due to object illegal error.");
                throw new WeIdBaseException(ErrorCode.DATA_TYPE_CASE_ERROR);
            }

            int creListSize = credentialPojoList.size();
            if (creListSize == 0) {
                logger.error(
                    "buildPdf4DefaultTpl due to credentialList size equal to zero error.");
                throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
            }

            //创建包含一个空白页的PDF
            PDDocument document = new PDDocument();

            //通过creListSize来新增PDF页面
            addPdfPage(creListSize, document);

            //遍历credentialList，把每一个cliam写入到pdf对应的page中
            addClaim2Pdf(credentialPojoList, document);

            //设置输出pdf文件的属性信息
            addAttributeInfo(document, pdfAttributeInfo);

            //定义OutputStream
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            //将outputstream写到byte[]
            document.save(out);
            byte[] ret = out.toByteArray();
            document.close();
            return ret;
        } catch (Exception e) {
            logger.error("buildPdf4DefaultTpl error.", e);
            throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
        }
    }

    /**
     * 把presentation数据写入指定PDF模板，输出PDF流.
     *
     * @param object serialize函数输入的object
     * @param document 指定PDF模板的PDDocument
     * @param pdfAttributeInfo  PDF协议数据
     * @param <T> JsonSerializer
     * @return PDF流数据
     * @throws WeIdBaseException exception
     */
    private  <T extends JsonSerializer> byte[] buildPdf4SpecTpl(
        T object,
        PDDocument document,
        PdfAttributeInfo pdfAttributeInfo) throws WeIdBaseException {

        try {
            PresentationE presentation = new PresentationE();
            CredentialPojo credentialPojo;
            LinkedHashMap<String, String> plainClaimMap = new LinkedHashMap<>(5);
            List<CredentialPojo> credentialPojoList = new ArrayList<>(3);
            List<CredentialPojo> creList = new ArrayList<>(1);

            //获取presentation中的credentialList
            if (object instanceof PresentationE) {
                presentation = (PresentationE) object;

                //处理credentialList不存在的情况
                if (presentation.getVerifiableCredential().size() == 0) {
                    logger.error(
                        "buildPdf4SpecTpl due to credentialList size equal to zero error.");
                    throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
                }

                //presentationE不存在多签情况，直接获取credentialList
                credentialPojoList = presentation.getVerifiableCredential();
            } else if (object instanceof CredentialPojo) {
                credentialPojo = (CredentialPojo) object;

                //多签情况递归获取最内层credentialList，否则直接获取credentialList
                if (credentialPojo.getClaim().containsKey("credentialList")
                    && credentialPojo.getClaim().size() == 1) {
                    getMultiSignClaim(credentialPojo, creList);
                    credentialPojoList = creList;
                } else {
                    credentialPojoList.add(credentialPojo);
                }
            } else if (object instanceof CredentialPojoList) {
                credentialPojoList = (CredentialPojoList) object;
            } else {
                logger.error(
                    "buildPdf4SpecTpl due to object illegal error.");
                throw new WeIdBaseException(ErrorCode.DATA_TYPE_CASE_ERROR);
            }

            int creListSize = credentialPojoList.size();

            Map<String, Object>[] salt = new HashMap[creListSize];
            Map<String, Object>[] claim = new HashMap[creListSize];
            StringBuilder prefix = new StringBuilder();

            //处理credentialList，把多级claimMap转为单级map
            for (int i = 0;i < creListSize; i++) {
                //利用cptId到链上获取CPT
                Integer cptId = credentialPojoList.get(i).getCptId();
                ResponseData<Cpt> res = cptService.queryCpt(cptId);
                Cpt cpt = res.getResult();
                Map<String, Object> cptMap = cpt.getCptJsonSchema();
                Map<String, Object> propMap = new HashMap<>(3);

                //多级cpt包含properties
                if (cptMap.containsKey("properties")) {
                    try {
                        propMap = DataToolUtils.objToMap(cptMap.get("properties"));
                    } catch (Exception e) {
                        logger.error("addClaim2Pdf error due to objToMap cptMap.", e);
                        throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
                    }
                }

                //从presentation获取salt和claim
                salt[i] = credentialPojoList.get(i).getSalt();
                claim[i] = credentialPojoList.get(i).getClaim();

                //获取claim的k-v数据
                if (salt[i] != null && claim[i] != null) {
                    buildDisclosureInfo(plainClaimMap, salt[i], claim[i], prefix, propMap, true);
                } else {
                    logger.error("addClaim2Pdf due claim or salt does not exist error.");
                    throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
                }
            }

            InputStream is = this
                .getClass()
                .getClassLoader()
                .getResourceAsStream("NotoSansCJKtc-Regular.ttf");
            TTFParser parser = new TTFParser();
            if (is == null) {
                logger.error(
                    "buildPdf4SpecTpl due to font stream is null error.");
                throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
            }
            TrueTypeFont font = parser.parse(is);
            PDType0Font fontChinese = PDType0Font.load(document, font, true);

            PDDocumentCatalog documentCatalog = document.getDocumentCatalog();
            PDAcroForm acroForm = documentCatalog.getAcroForm();

            if (acroForm == null) {
                logger.error(
                    "buildPdf4SpecTpl due to pdf template acroForm is null error.");
                throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
            }

            PDResources resources = new PDResources();
            resources.add(fontChinese);

            resources.put(COSName.getPDFName("NotoSansCJKTC"), fontChinese);
            String defaultAppearanceString = "/NotoSansCJKTC 0 Tf 0 g";
            acroForm.setDefaultAppearance(defaultAppearanceString);
            acroForm.setDefaultResources(resources);
            acroForm.setNeedAppearances(false);

            //遍历PDFDocumnet中的key值，设置相应的value值
            for (PDField field : acroForm.getFields()) {
                if (plainClaimMap.containsKey(field.getPartialName())) {
                    String text = String.valueOf(plainClaimMap.get(field.getPartialName()));
                    if (fontChinese.willBeSubset()) {
                        int offset = 0;
                        while (offset < text.length()) {
                            int codePoint = text.codePointAt(offset);
                            fontChinese.addToSubset(codePoint);
                            offset += Character.charCount(codePoint);
                        }
                    }
                    field.setValue(text);
                } else {
                    logger.error(
                        "buildPdf4SpecTpl due to pdf template doesn't match with claim error.");
                    throw new WeIdBaseException(ErrorCode.TRANSPORTATION_BASE_ERROR);
                }
            }

            //设置输出pdf文件的属性信息(PdfBaseData中每个字段），并关闭PDDocument
            addAttributeInfo(document, pdfAttributeInfo);

            //定义OutputStream
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            //设置嵌入字体子集
            fontChinese.subset();
            document.registerTrueTypeFontForClosing(font);

            //把PDF写入到OutputStream和文件中
            document.save(out);
            byte[] ret = out.toByteArray();
            document.close();
            return ret;
        } catch (Exception e) {
            logger.error("buildPdf4SpecTpl error.", e);
            throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
        }
    }

    /**
     * 把PDF流数据读出为PDDcoument数据，来获取PDF的属性信息并生成文件来验证存证.
     *
     * @param pdfTransportation  PDF流数据
     * @param pdfAttributeInfo 存PDF属性信息的PdfBaseData
     * @throws WeIdBaseException exception
     */
    private void resolvePdfStream(
        byte[] pdfTransportation,
        PdfAttributeInfo pdfAttributeInfo) throws WeIdBaseException {

        try {
            //加载文件流为PDDocument
            PDDocument document;

            if (pdfTransportation == null || pdfTransportation.length == 0) {
                logger.error("resolvePdfStream due to pdfTransportation byte[] is illegal error.");
                throw new WeIdBaseException(ErrorCode.ILLEGAL_INPUT);
            } else {
                document = PDDocument.load(parse(pdfTransportation));
            }

            //将PDF中属性信息解析到PdfBaseData数据结构中
            PDDocumentInformation pdd = document.getDocumentInformation();
            buildPdfDataFromPdf(pdd, pdfAttributeInfo);

            document.close();
        } catch (Exception e) {
            logger.error("resolvePdfStream error.", e);
            throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
        }
    }

    @Override
    public <T extends JsonSerializer> ResponseData<byte[]> serialize(
        T object,
        ProtocolProperty property) {

        logger.info(
            "begin to execute PdfTransportation serialization, property:{}.", property);
        logger.info(
            "input the object for PdfTransportation serialization, object:{}.", object);
        ResponseData<byte[]> errorCode1 = checkPara(object, property);
        if (errorCode1 != null) {
            return errorCode1;
        }

        try {
            //构建PDF协议数据
            PdfAttributeInfo pdfAttributeInfo = setPdfBaseData(object, property);

            //处理PDF显示信息和属性信息
            byte[] pdfFileByte = buildPdf4DefaultTpl(object, pdfAttributeInfo);

            logger.info("PdfTransportationImpl serialization finished.");
            return new ResponseData<>(pdfFileByte, ErrorCode.SUCCESS);
        } catch (WeIdBaseException e) {
            logger.error("[serialize] PdfTransportation serialization due to base error.", e);
            return new ResponseData<>(null, e.getErrorCode());
        } catch (Exception e) {
            logger.error("[serialize] PdfTransportation serialization due to unknown error.", e);
            return new ResponseData<>(null, ErrorCode.TRANSPORTATION_BASE_ERROR);
        }
    }

    @Override
    public <T extends JsonSerializer> ResponseData<Boolean> serialize(
        T object,
        ProtocolProperty property,
        String outputPdfFilePath) {

        try {
            if (outputPdfFilePath == null || outputPdfFilePath.length() == 0) {
                logger.error(
                    "[serialize] PdfTransportation serialization due to File Path illegal error.");
                return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
            }

            File file = createFileByPath(outputPdfFilePath);

            ResponseData<byte[]> res = serialize(object, property);
            if (res.getResult() == null) {
                logger.error("[serialize] PdfTransportation serialization due to serialize error.");
                return new ResponseData<>(
                    false, ErrorCode.getTypeByErrorCode(res.getErrorCode()));
            } else {
                //生成文件
                FileOutputStream outputStream  = new FileOutputStream(file);
                outputStream.write(res.getResult());
                outputStream.close();
            }
            return new ResponseData<>(true, ErrorCode.SUCCESS);
        } catch (WeIdBaseException e) {
            logger.error("[serialize] PdfTransportation serialization due to base error.", e);
            return new ResponseData<>(false, e.getErrorCode());
        } catch (Exception e) {
            logger.error("[serialize] PdfTransportation serialization due to unknown error.", e);
            return new ResponseData<>(false, ErrorCode.TRANSPORTATION_BASE_ERROR);
        }
    }

    @Override
    public <T extends JsonSerializer> ResponseData<byte[]> serializeWithTemplate(
        T object,
        ProtocolProperty property,
        String inputPdfTemplatePath) {

        logger.info(
            "[serialize] begin to execute PdfTransportation serialization, property:{}.", property);
        logger.info(
            "[serialize] input the object for PdfTransportation serialization, object:{}.", object);
        ResponseData<byte[]> errorCode1 = checkPara(object, property);
        if (errorCode1 != null) {
            return errorCode1;
        }

        try {
            //把PDF模板读成流数据
            PDDocument document;
            File file = new File(inputPdfTemplatePath);
            if (file.exists() && !file.isDirectory()) {
                try {
                    document = PDDocument.load(file);
                } catch (IOException e) {
                    logger.error("pdf template load error:{}.", ErrorCode.BASE_ERROR, e);
                    return new ResponseData<>(null,  ErrorCode.BASE_ERROR);
                }
            } else {
                logger.error("pdf template directory illegal:{}.", ErrorCode.ILLEGAL_INPUT);
                return new ResponseData<>(null,  ErrorCode.ILLEGAL_INPUT);
            }

            //输出PDF模板的bytes[],并计算keccak哈希值
            ByteArrayOutputStream tmpStream = new ByteArrayOutputStream();
            document.save(tmpStream);
            byte[] retBytes = tmpStream.toByteArray();
            String templateHash = getChecksum(retBytes);

            //构建PDF协议数据
            PdfAttributeInfo pdfAttributeInfo = setPdfBaseData(object, property);

            //设置PDF模板的id
            pdfAttributeInfo.setTemplateId(templateHash);

            //处理PDF显示信息和属性信息
            byte[] pdfFileByte = buildPdf4SpecTpl(object, document, pdfAttributeInfo);

            logger.info("PdfTransportationImpl serialization finished.");
            return new ResponseData<>(pdfFileByte, ErrorCode.SUCCESS);
        } catch (WeIdBaseException e) {
            logger.error("[serialize] PdfTransportation serialization due to base error.", e);
            return new ResponseData<>(null, e.getErrorCode());
        } catch (Exception e) {
            logger.error("[serialize] PdfTransportation serialization due to unknown error.", e);
            return new ResponseData<>(null, ErrorCode.TRANSPORTATION_BASE_ERROR);
        }
    }

    @Override
    public <T extends JsonSerializer> ResponseData<Boolean> serializeWithTemplate(
        T object,
        ProtocolProperty property,
        String inputPdfTemplatePath,
        String outputPdfFilePath) {

        try {
            if (outputPdfFilePath == null || outputPdfFilePath.length() == 0) {
                logger.error(
                    "[serialize] PdfTransportation serialization due to File Path illegal error.");
                return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
            }
            logger.info(
                "[serialize] input the object for PdfTransportation serialization with template,"
                + " object:{}", object);
            File file = createFileByPath(outputPdfFilePath);

            ResponseData<byte[]> res = serializeWithTemplate(
                object,
                property,
                inputPdfTemplatePath);
            if (res.getResult() == null) {
                logger.error(
                    "[serialize] PdfTransportation serialization "
                        + "due to serializeWithTemplate error.");
                return new ResponseData<>(
                    false, ErrorCode.getTypeByErrorCode(res.getErrorCode()));
            } else {
                FileOutputStream outputStream  = new FileOutputStream(file);
                outputStream.write(res.getResult());
                outputStream.close();
            }
            return new ResponseData<>(true, ErrorCode.SUCCESS);
        } catch (WeIdBaseException e) {
            logger.error(
                "[serializeWithTemplate] PdfTransportation serialization due to base error.", e);
            return new ResponseData<>(false, e.getErrorCode());
        } catch (Exception e) {
            logger.error(
                "[serializeWithTemplate] PdfTransportation serialization "
                    + "due to unknown error.", e);
            return new ResponseData<>(false, ErrorCode.TRANSPORTATION_BASE_ERROR);
        }
    }

    @Override
    public <T extends JsonSerializer> ResponseData<T> deserialize(
        byte[] pdfTransportation,
        Class<T> clazz,
        WeIdAuthentication weIdAuthentication) {

        //检查WeIdAuthentication合法性
        ErrorCode errorCode = checkWeIdAuthentication(weIdAuthentication);
        if (errorCode != ErrorCode.SUCCESS) {
            logger.error("[deserialize] checkWeIdAuthentication fail, errorCode:{}.", errorCode);
            return new ResponseData<>(null, errorCode);
        }
        
        //开始反序列化
        logger.info("begin to execute PdfTransportationImpl deserialization from InputStream.");
        try {
            PdfAttributeInfo pdfAttributeInfo = new PdfAttributeInfo();
            resolvePdfStream(pdfTransportation, pdfAttributeInfo);

            //创建编解码实体对象并对pdfBaseData中的数据进行解码
            EncodeData encodeData = new EncodeData(
                pdfAttributeInfo.getId(),
                pdfAttributeInfo.getAmopId(),
                String.valueOf(pdfAttributeInfo.getData()),
                weIdAuthentication
            );

            //根据编解码类型获取编解码枚举对象
            EncodeType encodeType = EncodeType.getEncodeType(pdfAttributeInfo.getEncodeType());
            if (encodeType == null) {
                return new ResponseData<>(null, ErrorCode.TRANSPORTATION_PROTOCOL_ENCODE_ERROR);
            }
            logger.info("decode by {}.", encodeType.name());

            //解码
            String presentationEStr = EncodeProcessorFactory.getEncodeProcessor(
                encodeType).decode(encodeData);

            String presentationEJson = DataToolUtils.convertUtcToTimestamp(presentationEStr);
            String presentationEJsonNew = presentationEJson;
            if (DataToolUtils.isValidFromToJson(presentationEJson)) {
                presentationEJsonNew = DataToolUtils.removeTagFromToJson(presentationEJson);
            }
            T object;
            Method method = getFromJsonMethod(clazz);
            if (method == null) {
                //调用工具的反序列化
                object = (T) DataToolUtils.deserialize(presentationEJsonNew, clazz);
            } else {
                object = (T) method.invoke(null, presentationEJsonNew);
            }

            //有模板的情况设置presentation的type属性
            if (!pdfAttributeInfo.getTemplateId().equals("null")
                && object instanceof PresentationE) {
                PresentationE presentationE = new PresentationE();
                presentationE = (PresentationE) object;
                List<String> typeList = presentationE.getType();
                typeList.add(CredentialConstant.PRESENTATION_PDF);
                presentationE.setType(typeList);
                logger.info("PdfTransportationImpl deserialization finished.");
                return new ResponseData<>((T)presentationE, ErrorCode.SUCCESS);
            } else {
                logger.info("PdfTransportationImpl deserialization finished.");
                return new ResponseData<>(object, ErrorCode.SUCCESS);
            }
        } catch (WeIdBaseException e) {
            logger.error("[deserialize] PdfTransportation deserialize due to base error.", e);
            return new ResponseData<>(null, e.getErrorCode());
        } catch (Exception e) {
            logger.error("PdfTransportationFactory deserialization due to unknown error.", e);
            return new ResponseData<>(null, ErrorCode.TRANSPORTATION_BASE_ERROR);
        }
    }

    @Override
    public <T extends JsonSerializer> Boolean verifyPdf(
        T object,
        String pdfTemplatePath,
        PdfAttributeInfo pdfAttributeInfo,
        byte[] serializePdf) {

        byte[] assemblePdf  = assemblePdf(object, pdfTemplatePath, pdfAttributeInfo);
        logger.info("[verifyPdf] verify pdf finished.");
        return comparePdf(assemblePdf, serializePdf);
    }

    @Override
    public PdfAttributeInfo getBaseData(byte[] pdfTransportation) {

        if (pdfTransportation == null || pdfTransportation.length == 0) {
            logger.error(
                "[getBaseData] get PdfBaseData from byte[] "
                    + "due to output file path is illegal error.");
            return null;
        }

        PdfAttributeInfo pdfAttributeInfo = new PdfAttributeInfo();
        resolvePdfStream(pdfTransportation, pdfAttributeInfo);
        return pdfAttributeInfo;
    }

    /**
     * 通过presentation和pdf模板组转pdf.
     *
     * @param object presentation
     * @param pdfTemplatePath pdf模板位置
     * @param pdfAttributeInfo pdf基本信息
     * @param <T> JsonSerializer
     * @return 组装pdf信息的byte数组
     */
    private  <T extends JsonSerializer> byte[] assemblePdf(
        T object,
        String pdfTemplatePath,
        PdfAttributeInfo pdfAttributeInfo) {

        try {
            //检查presentation完整性
            ErrorCode errorCode = checkProtocolData(object);
            if (errorCode != ErrorCode.SUCCESS) {
                logger.error("[assemblePdf] checkProtocolData fail, errorCode:{}.", errorCode);
                return null;
            }

            //检查Pdf模板路径合法性
            if (pdfTemplatePath == null || pdfTemplatePath.length() == 0) {
                logger.error(
                    "[assemblePdf] assemble pdf due to pdf  template path is illegal error.");
                return null;
            }

            //读取PDF模板
            PDDocument document;
            File file = new File(pdfTemplatePath);
            if (file.exists() && !file.isDirectory()) {
                try {
                    document = PDDocument.load(file);
                } catch (IOException e) {
                    logger.error("[assemblePdf] pdf template load error:{}.", ErrorCode.BASE_ERROR);
                    return null;
                }
            } else {
                logger.error(
                    "[assemblePdf] pdf template directory illegal:{}.", ErrorCode.ILLEGAL_INPUT);
                return null;
            }

            //处理PDF显示信息和属性信息
            byte[] pdfFileByte = buildPdf4SpecTpl(object, document, pdfAttributeInfo);

            logger.info("PdfTransportationImpl assemble finished.");
            return pdfFileByte;
        } catch (WeIdBaseException e) {
            logger.error("[assemblePdf] PdfTransportation serialization due to base error.", e);
            return null;
        } catch (Exception e) {
            logger.error("[assemblePdf] PdfTransportation serialization due to unknown error.", e);
            return null;
        }
    }

    /**
     * 比较两个pdf的byte是否一致.
     *
     * @param assemblePdf 组装的pdf
     * @param serializePdf 序列化生成的pdf
     * @return 两者一致返回true
     */
    private Boolean comparePdf(
        byte[] assemblePdf,
        byte[] serializePdf) {

        if (assemblePdf == null
            || assemblePdf.length == 0
            || serializePdf == null
            || serializePdf.length == 0) {

            logger.error(
                "[comparePdfHash] compare pdf hash by byte[] "
                    + "due to input parameter is illegal error.");
            return Boolean.FALSE;
        }

        if (Arrays.equals(assemblePdf, serializePdf)) {
            return Boolean.TRUE;
        } else {
            return Boolean.FALSE;
        }
    }

    /**
     * 构建协议实体数据.
     *
     * @param property 协议配置对象
     * @return 返回协议实体对象
     */
    private PdfAttributeInfo buildPdfData(ProtocolProperty property) {

        PdfAttributeInfo pdfAttributeInfo = new PdfAttributeInfo();
        pdfAttributeInfo.setVersion(version.getCode());
        pdfAttributeInfo.setEncodeType(property.getEncodeType().getCode());
        pdfAttributeInfo.setId(DataToolUtils.getUuId32());
        pdfAttributeInfo.setAmopId(fiscoConfig.getAmopId());
        return pdfAttributeInfo;
    }

    /**
     * 根据credentialList大小来新增PDF页面.
     *
     * @param creListSize credentialList包含元素个数
     * @param document 新增页面的PDF文档
     */
    private void addPdfPage(int creListSize, PDDocument document) {

        for (int i = 0; i < creListSize; i++) {
            PDPage page = new PDPage();
            document.addPage(page);
        }
    }

    /**
     * 把Claim数据写入到PDF文档中.
     *
     * @param credentialPojoList credentialPojo的List
     * @param document PDF文档
     */
    private void addClaim2Pdf(
        List<CredentialPojo> credentialPojoList,
        PDDocument document) throws WeIdBaseException {

        int pageAddNum = 0;
        int creListSize = credentialPojoList.size();

        //中间数据存储结构. 使用LinkedHashMap以保持顺序
        LinkedHashMap<String, String>[] disclosureInfo = new LinkedHashMap[creListSize];
        for (int i = 0; i < creListSize; i++) {
            CredentialPojo cre = credentialPojoList.get(i);

            //利用cptId到链上获取CPT
            Integer cptId = cre.getCptId();
            ResponseData<Cpt> res = cptService.queryCpt(cptId);
            Cpt cpt = res.getResult();
            Map<String, Object> cptMap = cpt.getCptJsonSchema();
            Map<String, Object> propMap;
            try {
                propMap = DataToolUtils.objToMap(cptMap.get("properties"));
            } catch (Exception e) {
                logger.error("addClaim2Pdf error due to objToMap cptMap.", e);
                throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
            }

            //从credential中获取Claim和Salt. Salt用于查询披露字段
            Map<String, Object> claim = cre.getClaim();
            Map<String, Object> salt = cre.getSalt();

            //生成一个中间数据
            disclosureInfo[i] = new LinkedHashMap<>();
            StringBuilder prefix = new StringBuilder();
            if (claim != null && salt != null) {
                buildDisclosureInfo(disclosureInfo[i], salt, claim, prefix, propMap, false);
            } else {
                logger.error("addClaim2Pdf due to claim or salt does not exist error.");
                throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
            }

            //把中间数据写入到对应PDF页面中
            if (i + pageAddNum <= document.getPages().getCount()) {
                pageAddNum = drawPdf(i + pageAddNum, document, disclosureInfo[i], cptMap);
            }
        }
    }

    /**
     * 把disclosureInfo中的数据写入PDF.
     *
     * @param pageNum 当前写入page的索引
     * @param document 待写入的PDF
     * @param disclosureInfo credentialList包含元素个数
     * @param cptJson 用于获取当前CLaim的title
     * @return 增对单条disclosureInfo信息跨行，以及Claim跨页情况，返回本函数新增的page数量
     */
    private int drawPdf(
        int pageNum,
        PDDocument document,
        LinkedHashMap<String, String> disclosureInfo,
        Map<String, Object> cptJson) throws WeIdBaseException {

        try {
            int pageAddNum = 0;

            //获取需要写入PDF的索引
            PDPageContentStream contents;
            contents = new PDPageContentStream(document, document.getPage(pageNum));

            //设置pdf中文字体
            InputStream is = this.getClass()
                .getClassLoader()
                .getResourceAsStream("NotoSansCJKtc-Regular.ttf");
            logger.error("InputStream:" + is.available());
            PDType0Font fontChinese = PDType0Font.load(document, is);

            //为当前页面加入标题
            if (cptJson.containsKey("title")) {
                String title = String.valueOf(cptJson.get("title"));
                addContent(contents, title, POS_TITLE_X, POS_TITLE_Y, fontChinese, FONT_SIZE_TITLE);
            }

            //设置写入内容的初始位置
            float pos = POS_CONTENT_Y;

            //遍历disclosureInfo写入到PDF中
            for (Map.Entry<String, String> entry : disclosureInfo.entrySet()) {
                String output = entry.getKey() + " : ";
                output = output + entry.getValue();

                //获取当前字符串长度并处理多行情况
                float outputLength = calcStrLength(output, FONT_SIZE_CONTENT, fontChinese);
                ArrayList<String> lines = new ArrayList<>();
                int lineSize;
                if (outputLength > MARGIN) {
                    buildLines(output, FONT_SIZE_CONTENT, fontChinese, lines);
                    lineSize = lines.size();

                    //输出当前行的lines
                    addMultiLine2Pdf(
                        lineSize,
                        contents,
                        FONT_SIZE_CONTENT,
                        fontChinese,
                        pos,
                        lines);
                    pos = pos - 15 * (lineSize - 1);
                    pos = pos - 30;
                } else {
                    addContent(
                        contents,
                        output,
                        POS_CONTENT_X,
                        pos, fontChinese,
                        FONT_SIZE_CONTENT);
                    pos = pos - 30;
                }

                //单个Claim跨多页情况
                if (pos < BOTTOM) {
                    //关闭旧页面
                    contents.close();
                    PDPage page = new PDPage();
                    document.addPage(page);
                    //用pageAddNum告诉外层已经新增了一页
                    contents = new PDPageContentStream(document, document.getPage(pageNum + 1));
                    pageAddNum++;

                    //设置新页面的位置
                    pos = POS_CONTENT_Y;
                }
            }
            contents.close();
            return pageAddNum;
        } catch (Exception e) {
            logger.error("addData2Pdf error.", e);
            throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
        }
    }

    /**
     * 将OutputStream转为InputStream.
     *
     * @param out OutputStream
     * @return InputStream
     */
    private ByteArrayInputStream parse(byte[] out) {

        return new ByteArrayInputStream(out);
    }

    /**
     * 计算指定路径文件的哈希值.
     *
     * @param pdfFileByte 输入文件路径
     * @return 返回文件的Keccak-256哈希值
     */
    private String getChecksum(byte[] pdfFileByte) {

        //使用web3j中的sha3算法：keccak-256
        byte[] digest = DataToolUtils.sha3(pdfFileByte);
        return Numeric.toHexString(digest);
    }

    /**
     * 检查serialize函数参数.
     *
     * @param object 协议存储的实体数据对象
     * @param property 加密属性信息
     * @param <T> JsonSerializer
     * @return 如果出错返回错误码，否则返回空
     */
    private <T extends JsonSerializer> ResponseData<byte[]> checkPara(
        T object,
        ProtocolProperty property) {

        //检查协议配置完整性
        ErrorCode errorCode = checkEncodeProperty(property);
        if (errorCode != ErrorCode.SUCCESS) {
            logger.error("checkEncodeProperty fail, errorCode:{}.", errorCode);
            return new ResponseData<>(null, errorCode);
        }

        //检查presentation完整性
        errorCode = checkProtocolData(object);
        if (errorCode != ErrorCode.SUCCESS) {
            logger.error("checkProtocolData fail, errorCode:{}.", errorCode);
            return new ResponseData<>(null, errorCode);
        }
        return null;
    }

    /**
     * 设置PDF协议数据实体.
     *
     * @param object 协议存储的实体数据对象
     * @param property 加密属性信息
     * @param <T> JsonSerializer
     * @return 返回PDF协议数据实体对象
     */
    private <T extends JsonSerializer> PdfAttributeInfo setPdfBaseData(
        T object,
        ProtocolProperty property) {

        //构建PDF协议数据
        PdfAttributeInfo pdfAttributeInfo = buildPdfData(property);
        logger.info("encode by {}.", property.getEncodeType().name());

        //非加密情况直接设置PDF协议中data数据
        if (property.getEncodeType() != EncodeType.CIPHER) {
            pdfAttributeInfo.setData(object.toJson());
        } else {
            //加密情况，构建编解码数据，加密数据，设置data属性
            EncodeData encodeData = new EncodeData(
                pdfAttributeInfo.getId(),
                pdfAttributeInfo.getAmopId(),
                object.toJson(),
                super.getVerifiers()
                    );
            String data = EncodeProcessorFactory.getEncodeProcessor(
                property.getEncodeType()).encode(encodeData);
            pdfAttributeInfo.setData(data);
        }
        return pdfAttributeInfo;
    }

    /**
     * 处理多签情况，获取最内层的credentialList.
     *
     * @param credentialPojo 多签的credentialPojo
     * @param creList 用于返回的最内层credentialList
     * @return 最内层的credentialList
     */
    private List<CredentialPojo> getMultiSignClaim(
            CredentialPojo credentialPojo,
            List<CredentialPojo> creList) {

        Map<String, Object> claim = credentialPojo.getClaim();

        //如果是多签情况，claim只包含一个key值，且类型为credentialList
        if (claim.containsKey("credentialList")  && claim.size() == 1) {
            Object obj = claim.get("credentialList");
            if (!(obj instanceof List)) {
                logger.error("getMultiSignClaim error.");
                throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
            }
            ArrayList<Object> objList = (ArrayList<Object>) obj;

            //找出credentialList中多签的CredentialPojo进行递归
            CredentialPojo cp = null;
            List<CredentialPojo> credentialPojos = new ArrayList<>(2);
            for (Object innerCredentialObject : objList) {
                Map<String, Object> map = (Map<String, Object>) innerCredentialObject;
                try {
                    CredentialPojo innerCredentialPojo = DataToolUtils.mapToObj(
                        map,
                        CredentialPojo.class);

                    //处理objList内无多签credential情况
                    credentialPojos.add(innerCredentialPojo);

                    if (innerCredentialPojo.getClaim().containsKey("credentialList")
                        && innerCredentialPojo.getClaim().size() == 1) {
                        cp = innerCredentialPojo;
                        break;
                    }
                } catch (Exception e) {
                    logger.error("getMultiSignClaim error due to:" + e.getMessage());
                    throw new WeIdBaseException(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR);
                }
            }
            if (cp == null) {
                creList.addAll(credentialPojos);
            } else {
                credentialPojos.clear();
                getMultiSignClaim(cp, creList);
            }
        } else {
            creList.add(credentialPojo);
        }
        return creList;
    }

    private File createFileByPath(String outputPdfFilePath) {

        try {
            String fileName;
            File file = new File(outputPdfFilePath);

            //outputPdfFilePath是文件还是路径
            if (outputPdfFilePath.contains(FILE_SEPARATOR) && outputPdfFilePath.substring(
                outputPdfFilePath.lastIndexOf(FILE_SEPARATOR)).equals(PDF_SUFFIX)) {
                file = new File(outputPdfFilePath);

                //如果文件所属目录不存在就创建目录
                String tempFileName = file.getName();
                String pathName = outputPdfFilePath.replace(tempFileName, "");
                File tempFile = new File(pathName);
                if (!tempFile.exists()) {
                    if (!tempFile.mkdirs()) {
                        logger.error("createFileByPath due to create directory error.");
                        throw new WeIdBaseException(ErrorCode.BASE_ERROR);
                    }
                    file = new File(outputPdfFilePath);
                }
            } else {
                Calendar calendar = Calendar.getInstance();

                //文件路径不存在，则新建目录，并使用默认文件名新建文件
                if (!file.exists()) {
                    if (!file.mkdirs()) {
                        logger.error("createFileByPath due to create directory error.");
                        throw new WeIdBaseException(ErrorCode.BASE_ERROR);
                    }
                    fileName = outputPdfFilePath
                        + PATH_LINKER + calendar.getTimeInMillis() + PDF_SUFFIX;
                    file = new File(fileName);
                    //文件路径不存在，则新建目录，并使用默认文件名新建文件
                } else {
                    fileName = outputPdfFilePath
                        + PATH_LINKER + calendar.getTimeInMillis() + PDF_SUFFIX;
                    file = new File(fileName);
                }
            }
            return file;
        } catch (Exception e) {
            logger.error("createFileByPath error.", e);
            throw new WeIdBaseException(ErrorCode.BASE_ERROR);
        }
    }
}