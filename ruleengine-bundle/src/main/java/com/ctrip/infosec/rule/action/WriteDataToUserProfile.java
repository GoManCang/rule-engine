package com.ctrip.infosec.rule.action;

import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.resource.DataProxy;
import com.ctrip.infosec.sars.util.SpringContextHolder;
import com.ctrip.sec.userprofile.contract.venusapi.DataProxyVenusService;
import com.ctrip.sec.userprofile.vo.content.request.DataProxyRequest;
import com.ctrip.sec.userprofile.vo.content.response.DataProxyResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;

/**
 * Created by lpxie on 15-4-20.
 * 这个类主要是把数据写进userProfileInfo
 * 调用DataProxy的commonService的addData
 */
public class WriteDataToUserProfile
{
    private static Logger logger = LoggerFactory.getLogger(WriteDataToUserProfile.class);

    /**
     * 把数据写进userProfile
     * @param values tag 和 对应的值
     * @param pkgValue 主键 比如用户的uid值
     * @param storeType 存储类型 1，hbase 2,redis
     * @return 返回执行的结果状态
     */
    public static Map writeData(Map values,String pkgValue,int storeType)
    {
        beforeInvoke();
        try
        {
            Map<String,Object> params = new HashMap();
            params.put("tableName","UserProfileInfo");
            params.put("pkValue",pkgValue);
            params.put("storageType",storeType);//1为hbase 和redis,2为redis
            params.put("values",values);
            DataProxyRequest request = new DataProxyRequest();
            request.setServiceName("CommonService");
            request.setOperationName("addData");
            request.setParams(params);

            List<DataProxyRequest> requests = new ArrayList<DataProxyRequest>();
            requests.add(request);
            DataProxyVenusService dataProxyVenusService = SpringContextHolder.getBean(DataProxyVenusService.class);
            List<DataProxyResponse> responses = dataProxyVenusService.dataproxyQueries(requests);
            if(responses != null && responses.size()>0)
            {
                int resultCode = responses.get(0).getRtnCode();
                if(resultCode == 0)
                {
                    return responses.get(0).getResult();
                }
            }
        }
        catch (Exception ex) {
        fault();
        logger.error(Contexts.getLogPrefix() + "invoke WriteDataToUserProfile.writeData fault.", ex);
    } finally {
        afterInvoke("WriteDataToUserProfile.writeData");
    }
        return null;
    }

    /**
     * 从userProfile查询数据
     * @param tags 只要查询的数据的tag 应该是和写入的时候对应的 比如 MOB_BOUND，RECENT_IP
     * @param pkgValue 要查询的主键的值 比如uid的值
     * @param storeType 存储的类型 1，hbase,2 ,redis
     * @param length 要查询的数据的长度，有可能查出的数据是list
     * @return
     */
    public static Map readData(List<String> tags,String pkgValue,int storeType,int length)
    {
        beforeInvoke();
        try
        {
            Map<String,Object> newParams = new HashMap();
            newParams.put("tableName","UserProfileInfo");
            newParams.put("pkValue",pkgValue);
            newParams.put("storageType",storeType);//1为hbase 和redis,2为redis
            newParams.put("colNames",tags);
            newParams.put("length",length);
            DataProxyRequest request = new DataProxyRequest();
            request.setServiceName("CommonService");
            request.setOperationName("getData");
            request.setParams(newParams);

            List<DataProxyRequest> requests = new ArrayList<DataProxyRequest>();
            requests.add(request);
            DataProxyVenusService dataProxyVenusService = SpringContextHolder.getBean(DataProxyVenusService.class);
            List<DataProxyResponse> responses = dataProxyVenusService.dataproxyQueries(requests);
            if(responses != null && responses.size()>0)
            {
                int resultCode = responses.get(0).getRtnCode();
                if(resultCode == 0)
                {
                    return responses.get(0).getResult();
                }
            }
        }
        catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke WriteDataToUserProfile.readData fault.", ex);
        } finally {
            afterInvoke("WriteDataToUserProfile.readData");
        }
        return null;
    }
}
