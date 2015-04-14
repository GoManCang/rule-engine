/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.converter;

import javax.annotation.Resource;
import org.springframework.stereotype.Service;

/**
 *
 * @author zhengbaiyun
 */
@Service
public class ConverterLocator {

    //
    @Resource(name = "ip2ProvinceCityConverter")
    private Converter ip2ProvinceCityConverter;
    //
    @Resource(name = "mobile2ProvinceCityConverter")
    private Converter mobile2ProvinceCityConverter;
    //
    @Resource(name = "userProfileTagsConverter")
    private Converter userProfileTagsConverter;
    //
    @Resource(name = "crmUserInfoConverter")
    private Converter crmUserInfoConverter;
    //
    @Resource(name = "cardInfoDecryptConverter")
    private Converter cardInfoDecryptConverter;
    //
    @Resource(name = "airport3Code2CityConverter")
    private Converter airport3Code2CityConverter;

    /**
     * 根据PreActionEnums查找对应的Converter
     */
    public Converter getConverter(PreActionEnums preAction) {
        switch (preAction) {
            case Ip2ProvinceCity:
                return ip2ProvinceCityConverter;
            case Mobile2ProvinceCity:
                return mobile2ProvinceCityConverter;
            case UserProfileTags:
                return userProfileTagsConverter;
            case CrmUserInfo:
                return crmUserInfoConverter;
            case CardInfoDecrypt:
                return cardInfoDecryptConverter;
            case Airport3Code2City:
                return airport3Code2CityConverter;
            default:
                return null;
        }
    }
}
