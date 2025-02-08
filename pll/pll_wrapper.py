import ctypes
import os
import platform

class PLLWrapper:
    def __init__(self):
        # 加载共享库
        system = platform.system()
        dll_path = {
            'Linux': 'libpll.so',
            'Windows': 'pll.dll'
        }.get(system, None)
        if not dll_path:
            raise OSError("Unsupported OS")
        
        self.lib = ctypes.CDLL(dll_path)
        
        # 定义函数原型
        self.lib.create_pll.restype = ctypes.c_void_p
        self.lib.free_pll.argtypes = [ctypes.c_void_p]
        
        self.lib.construct_index.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_bool
        ]
        self.lib.k_distance_query.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_int)
        ]
        self.lib.store_index.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.lib.store_index.restype = ctypes.c_bool
        
        # 创建PLL实例
        self.pll_ptr = self.lib.create_pll()

    def __del__(self):
        if self.pll_ptr:
            self.lib.free_pll(self.pll_ptr)

    def store_index(self, path):
        return self.lib.store_index(
            ctypes.c_void_p(self.pll_ptr),  # 确保指针正确传递
            path.encode('utf-8')
        )

