import os
import sys
import platform
import logging
import zipfile
import tarfile
import stat
import aiohttp
import asyncio
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class AssetManager:
    """
    军火库管理器：负责自动下载和管理免安装的便携式安全工具。
    实现'零依赖'的核心组件。
    """
    
    # 定义需要的便携式工具及其下载源 (以Windows为例，实际代码需判断OS)
    TOOLS = {
        "nuclei": {
            "url": "https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_windows_amd64.zip",
            "binary_name": "nuclei.exe" if platform.system() == "Windows" else "nuclei",
            "description": "基于模板的高级漏洞扫描器"
        },
        "subfinder": {
            "url": "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_windows_amd64.zip",
            "binary_name": "subfinder.exe" if platform.system() == "Windows" else "subfinder",
            "description": "被动子域名发现工具"
        }
        # 可以继续添加 httpx, naabu 等
    }

    def __init__(self, base_dir: str = None):
        if base_dir:
            self.bin_dir = Path(base_dir)
        else:
            # 默认为项目根目录下的 bin 文件夹
            self.bin_dir = Path(__file__).parent.parent.parent / "bin"
        
        self.bin_dir.mkdir(parents=True, exist_ok=True)

    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """获取工具的可执行路径，如果不存在则返回None"""
        if tool_name not in self.TOOLS:
            return None
        
        binary_name = self.TOOLS[tool_name]["binary_name"]
        tool_path = self.bin_dir / binary_name
        
        if tool_path.exists():
            return str(tool_path)
        return None

    async def ensure_tool(self, tool_name: str) -> str:
        """
        确保工具存在。如果不存在，自动下载并解压。
        返回工具的绝对路径。
        """
        if tool_name not in self.TOOLS:
            raise ValueError(f"未知工具: {tool_name}")

        tool_path = self.get_tool_path(tool_name)
        if tool_path:
            return tool_path

        logger.info(f"正在自动部署工具: {tool_name} ...")
        await self._download_and_extract(tool_name)
        
        return str(self.bin_dir / self.TOOLS[tool_name]["binary_name"])

    async def _download_and_extract(self, tool_name: str):
        url = self.TOOLS[tool_name]["url"]
        filename = url.split("/")[-1]
        download_path = self.bin_dir / filename

        # 下载
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status != 200:
                    raise Exception(f"下载失败: {url} status={response.status}")
                
                with open(download_path, 'wb') as f:
                    while True:
                        chunk = await response.content.read(1024*1024)
                        if not chunk:
                            break
                        f.write(chunk)

        # 解压
        logger.info(f"正在解压 {filename}...")
        if filename.endswith(".zip"):
            with zipfile.ZipFile(download_path, 'r') as zip_ref:
                zip_ref.extractall(self.bin_dir)
        elif filename.endswith(".tar.gz"):
            with tarfile.open(download_path, "r:gz") as tar:
                tar.extractall(self.bin_dir)
        
        # 清理压缩包
        os.remove(download_path)
        logger.info(f"工具 {tool_name} 部署完成")

# 全局单例
asset_manager = AssetManager()
