import com.ctrip.datasource.locator.DataSourceLocator;

import javax.sql.DataSource;

/**
 * Created by yxjiang on 2015/7/21.
 */
public class AllInOneTest {
    public static void main(String[] args) throws Exception {
        DataSource dataSource = DataSourceLocator.newInstance().getDataSource("CardRiskDB_INSERT_1_SH");
        System.out.println(dataSource);
    }
}
