from graph_loader import GraphLoader
from pll.pll_wrapper import *
from collections import defaultdict
import struct
from collections import defaultdict
def build_wordindex(graph):
    """
    构建关键词倒排索引
    结构：{keyword: [(node_id, level), ...]} 按level降序排列
    """
    wordindex = defaultdict(list)
    
    for node in graph.vertices:
        if len(node) != 3:
            raise ValueError(f"Invalid vertex format: {node}")
            
        node_id, kw_id, level = node
        # 支持多关键字类型（整数或字符串）
        keyword = str(kw_id).strip().lower()  # 标准化关键词格式
        
        wordindex[keyword].append( (int(node_id), int(level)) )
    
    # 按level降序排序，node_id升序作为次排序键
    for kw in wordindex:
        wordindex[kw].sort(key=lambda x: (-x[1], x[0]))
    
    return dict(wordindex)

def build_entryindex(graph, wordindex, max_level):
    """
    构建层级入口索引
    结构：{node: {level: entry}}
    
    规则：
    - wordindex[node] 的值列表 **按元组第二个元素降序排序**。
    - 对于 `level`，找到 **第一个 (v1, v2) 使得 v2 <= level**，取其 **列表索引** 作为 entry 存入 entryindex[node][level]。
    - 若 `level` 无法匹配任何 `v2`，则沿用上一层的 `entry`，确保 `0` 到 `max_level` 皆有值。
    """
    entryindex = defaultdict(dict)

    for node, word,node_level in graph.vertices:
        node = str(node)

        # 确保 node 在 wordindex 中
        if node not in wordindex:
            continue

        # 按照 (v1, v2) 的 v2 降序排列
        sorted_word_list = sorted(wordindex[node], key=lambda x: int(x[1]), reverse=True)

        # 记录上一层的 entry（用于填补缺失值）
        last_entry = 0  

        # 遍历 level，查找满足条件的 entry
        for level in range(max_level + 1):
            entry = next((i for i, (_, v2) in enumerate(sorted_word_list) if int(v2) <= level), last_entry)
            entryindex[node][level] = entry
            last_entry = entry  # 记录当前层的 entry，供下层使用

    return dict(entryindex)

def build_queryindex(graph):
    """
    构建PLL查询索引
    """
    pll = PLLWrapper()
    
    # 输入验证
    if not all(len(edge) == 2 for edge in graph.edges):
        raise ValueError("Invalid edge format")
    
    # 转换为节点ID列表
    edge_list = [(int(src), int(dest)) for src, dest in graph.edges]
    print(f"edge_list:{edge_list}")
    # 构建索引参数可配置化
    pll.construct_index(
        edge_list=edge_list,
        K=10,                   # 控制索引精度
        directed=False         # 无向图
        # distance_heuristic=True # 启用距离启发式
    )
    pll.store_index('queryindex_fb3')
    print("store index done.now print:")
    pll.print_index()
    print(f"pll11.k_distance_query(1,2,1)={pll.k_distance_query(1,1,1)}")
    return pll

def search(enc_vertex, k,pll):

    k_distance = [1,2,3]

    result = []
    for distance in k_distance:
        diss = pll.k_distance_query(enc_vertex, distance,k)
        result.append(diss)
    return result[:k]

if __name__ == "__main__":
    # 初始化加载器
    loader = GraphLoader()
    
    # 测试数据加载
    test_graph = loader.build_graph(
        nodes_file=r"E:\phknk\scheme\ph_knk\test3e.txt",
        edges_file=r"E:\phknk\scheme\ph_knk\testedges.txt"
    )
    
    # 打印顶点示例（验证输入格式）
    print("Sample vertices:")
    print(test_graph.vertices[:3])  # 显示前3个顶点
    
    # 构建索引系统
    word_index = build_wordindex(test_graph)
    entry_index = build_entryindex(test_graph,word_index,4)
    query_index = build_queryindex(test_graph)

    write_binary_index('wordindex.bin',word_index)
    write_binary_index('entryindex.bin',entry_index)

    # word_index_load = load_binary_index('wordindex_fb.bin')
    # entry_index_load = load_binary_index('entryindex_fb.bin')
    # print(f"wordindex:{word_index}")
    # print(f"wordinedx_load:{word_index_load}")
    # print(f"entryindex:{entry_index}")
    # print(f"entry_load:{entry_index_load}")

    pll11 = PLLWrapper()
    qq = pll11.load_index('queryindex_fb3')
    pll11.print_index()
    vv = pll11.k_distance_query(1,2,1)
    test = pll11.shortest_distance(0,2)
    print(f"pll11.k_distance_query(1,2,1)={vv}")
    print(f"pll11.shortest_distance(1,2)={test}")

    # # print(f"result:{result}")
    # # 打印索引统计信息
    # print("\nIndex Statistics:")
    print(word_index)
    print(entry_index)
    # print(f"Unique Keywords: {len(word_index)}")
    # print(f"Max Level Entries: {max(len(v) for v in entry_index.values()) if entry_index else 0}")
    # # print(f"PLL Coverage: {query_index.coverage_rate():.2%}")
    # print(f"PLL index: {query_index}")