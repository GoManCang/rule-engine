package com.ctrip.infosec.rule.utils;

import java.util.List;

import com.google.common.collect.Lists;



/**
 * 类笛卡儿积工具类
 * @author sjchi
 * @date 2015年7月5日 上午9:21:55
 */
public class UnionUtil {
    
    /**
     * 将两组元素集合进行笛卡尔积操作返回的INode集合可以通过{@link INode#searchData(INodeDataHandle)}深入遍历元素<br/>
     * 单元素和结合后的复合元素都继承自{@link INode}<br/>
     * 如果有一项数组元素为空，则直接返回不为空的列表
     * @param g1
     * @param g2
     * @return
     */
	public static <T> List<INode<T>> union(List<INode<T>> g1, List<INode<T>> g2) {
		
        List<INode<T>> result = Lists.newArrayList();
        
        if(g1.size() > 0 && g2.size() == 0) return g1;
        if(g1.size() == 0 && g2.size() > 0) return g2;
        
        for(INode<T> g1Node : g1){
            for(INode<T> g2Node : g2){
                result.add(new ComponentUnionNode<T>(g1Node,g2Node));
            }
        }
        
        return result;
    }
    
    public static void main(String[] args) {
        
        /**
         * 
         * UnionNode node1G1 = new UnionNode<String>("a");
         * UnionNode node2G1 = new UnionNode<String>("a");
    
         * List<UnionNode> list1
         * List<UnionNode> list2
         * 
         * List<UnionNode> list3 = UnionUtils.union(list1,list2);
         * 
         * for(UnionNode node : list3){
         *      node.get();
         * }
         * 
         * */
        
    	INode<String> node1G1 = new UnionNode<String>("a");
    	INode<String> node2G1 = new UnionNode<String>("b");
    	INode<String> node3G1 = new UnionNode<String>("c");
        List<INode<String>> g1 = Lists.newArrayList(node1G1,node2G1,node3G1);
        
        INode<String> node1G2 = new UnionNode<String>("1");
        INode<String> node2G2 = new UnionNode<String>("2");
        INode<String> node3G2 = new UnionNode<String>("3");
        List<INode<String>> g2 = Lists.newArrayList(node1G2,node2G2,node3G2);
        
        List<INode<String>> g3 = UnionUtil.union(g1,g2);
        
        INode<String> node1G4 = new UnionNode<String>("x");
        INode<String> node2G4 = new UnionNode<String>("y");
        INode<String> node3G4 = new UnionNode<String>("z");
        List<INode<String>> g4 = Lists.newArrayList(node1G4,node2G4,node3G4);
        
        g3 = UnionUtil.union(g3,g4);
        
        for(INode<String> node : g3){
            
        	final StringBuffer buffer = new StringBuffer().append("{");
            node.searchData(new INodeDataHandle<String>() {

                @Override
                public void handle(String data) {
                    buffer.append(data).append(",");
                }
            });
            buffer.append("}");
            
            System.out.println(buffer.toString());
        }
        
    }
    
    /**
     * 元素节点，其中T为原始数据
     */
    public static interface INode<T>{
        
        /**
         * 获取原始数据
         */
        public T getData();

        /**
         * 深入遍历节点
         */
        public void searchData(INodeDataHandle<T> handle);
        
    }
    
    /**
     * 单元素节点
     */
    public static class UnionNode<T> implements INode<T>{

        private T data;
        
        public UnionNode(T data) {
            this.data = data;
        }
        
        @Override
        public T getData() {
            return data;
        }

        @Override
        public void searchData(INodeDataHandle<T> handle) {
            handle.handle(data);
        }

    }
    
    /**
     * 符合元素节点
     */
    public static class ComponentUnionNode<T> implements INode<T>{
        
        private INode<T> node1;
        private INode<T> node2;

        public ComponentUnionNode(INode<T> node1, INode<T> node2) {
            this.node1 = node1;
            this.node2 = node2;
        }

        @Override
        public T getData() {
            throw new UnsupportedOperationException();
        }

        @Override
        public void searchData(INodeDataHandle<T> handle) {
            node1.searchData(handle);
            node2.searchData(handle);
        }
        
    }
    
    /**
     * 自定义数据处理接口
     */
    public static interface INodeDataHandle<T>{
        
        public void handle(T data);
        
    }
    

}
