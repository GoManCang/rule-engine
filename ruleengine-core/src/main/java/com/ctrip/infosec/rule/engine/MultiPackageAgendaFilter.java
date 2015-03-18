/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.engine;

import java.util.List;
import org.drools.runtime.rule.Activation;
import org.drools.runtime.rule.AgendaFilter;

public class MultiPackageAgendaFilter implements AgendaFilter {

    private List<String> packageNames;

    public MultiPackageAgendaFilter(List<String> packageNames) {
        this.packageNames = packageNames;
    }

    @Override
    public boolean accept(Activation activation) {
        String pkgName = (String) activation.getRule().getPackageName();
        return packageNames.contains(pkgName);
    }
}
