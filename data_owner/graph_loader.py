import csv
import openpyxl
from openpyxl import Workbook
import re

class Graph:
    def __init__(self):
        self.vertices = []
        self.edges = []

class GraphLoader:
    def __init__(self):
        self._delimiter = None  # 动态存储检测到的分隔符
    
    def _detect_delimiter(self, file_path, sample_lines=5):
        """自动检测文本文件分隔符"""
        delimiters = [',', '\t', ';', '|', ' ']
        delimiter_counts = {delim: 0 for delim in delimiters}
        
        with open(file_path, 'r', newline='') as f:
            for _ in range(sample_lines):
                line = f.readline()
                if not line:
                    break
                for delim in delimiters:
                    delimiter_counts[delim] += line.count(delim)
        
        # 选择出现频率最高的分隔符
        self._delimiter = max(delimiter_counts, key=delimiter_counts.get)
        return self._delimiter

    def _get_file_type(self, file_path):
        """支持更多文件类型判断"""
        ext = file_path.split('.')[-1].lower()
        if ext in ('csv', 'txt', 'dat'):
            return 'text'
        elif ext == 'xlsx':
            return 'excel'
        raise ValueError(f"Unsupported file type: {ext}")

    def _read_text_file(self, file_path):
        """智能读取文本文件"""
        if not self._delimiter:
            self._detect_delimiter(file_path)
        
        with open(file_path, 'r', newline='') as f:
            # 自动跳过空行
            reader = csv.reader(f, delimiter=self._delimiter)
            for row in reader:
                cleaned_row = [cell.strip() for cell in row if cell.strip()]
                if cleaned_row:  # 忽略空行
                    yield cleaned_row

    def _read_excel_file(self, file_path, sheet_name=None):
        """高效读取Excel文件"""
        wb = openpyxl.load_workbook(file_path, read_only=True)
        ws = wb[sheet_name] if sheet_name else wb.active
        
        for row in ws.iter_rows(values_only=True):
            cleaned_row = [str(cell).strip() if cell is not None else '' for cell in row]
            if any(cleaned_row):  # 忽略空行
                yield cleaned_row

    def _validate_numeric(self, value):
        """增强型数字验证"""
        try:
            return int(float(value))  # 支持科学计数法和浮点数
        except (ValueError, TypeError):
            return None

    def load_nodes(self, file_path, sheet_name=None):
        """增强节点加载"""
        node_word_levels = []
        file_type = self._get_file_type(file_path)
        
        reader = lambda: self._read_excel_file(file_path, sheet_name) if file_type == 'excel' else self._read_text_file(file_path)
        
        for row in reader():
            if len(row) >= 2:
                node_id = self._validate_numeric(row[0])
                word_id = self._validate_numeric(row[1])
                level = self._validate_numeric(row[2])
                # if node_id is not None and level is not None:
                    # if node_id in node_levels:
                    #     raise ValueError(f"Duplicate node ID: {node_id}")
                node_word_levels.append((node_id,word_id,level))
        return node_word_levels

    def load_edges(self, file_path, sheet_name=None):
        """增强边加载"""
        edges = []
        file_type = self._get_file_type(file_path)
        
        reader = lambda: self._read_excel_file(file_path, sheet_name) if file_type == 'excel' else self._read_text_file(file_path)
        
        for row in reader():
            if len(row) >= 2:
                src = self._validate_numeric(row[0])
                dest = self._validate_numeric(row[1])
                if src is not None and dest is not None:
                    # if (src, dest) in edges:
                    #     raise ValueError(f"Duplicate edge: ({src}, {dest})")
                    edges.append((src, dest))
        return edges

    def build_graph(self, nodes_file, edges_file, sheet_names=None):
        """增强图构建"""
        graph = Graph()
        
        # 处理可选的sheet名称
        node_sheet = sheet_names[0] if isinstance(sheet_names, (list, tuple)) else None
        edge_sheet = sheet_names[1] if isinstance(sheet_names, (list, tuple)) else None
        
        # 加载数据
        nodes = self.load_nodes(nodes_file, node_sheet)
        edges = self.load_edges(edges_file, edge_sheet)
        
        # 验证边数据完整性
        # all_node_ids = set(nodes.keys())
        # for src, dest in edges:
        #     if src not in all_node_ids:
        #         raise ValueError(f"Edge source node {src} not found in nodes")
        #     if dest not in all_node_ids:
        #         raise ValueError(f"Edge destination node {dest} not found in nodes")
        
        graph.vertices = nodes
        graph.edges = edges
        return graph


# # 复杂数据场景测试
# loader = GraphLoader()

# # 案例1：处理制表符分隔的TXT文件
# tab_graph = loader.build_graph(
#     nodes_file="./test3e.txt",
#     edges_file="./testedges.txt"
# )
# print(tab_graph.vertices)
# # 案例2：处理多工作表的Excel文件
# excel_graph = loader.build_graph(
#     nodes_file="data/graph_data.xlsx",
#     edges_file="data/graph_data.xlsx",
#     sheet_names=("NodesSheet", "EdgesSheet")
# )

# # 案例3：处理包含科学计数法的数据
# special_num_graph = loader.build_graph(
#     nodes_file="data/scientific_nodes.csv",
#     edges_file="data/scientific_edges.csv"
# )