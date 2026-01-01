"""Docker容器管理器。"""
import asyncio
import docker
from typing import Optional, Dict, Any
from docker.errors import DockerException, ContainerError, ImageNotFound


class DockerManager:
    """Docker容器管理器。"""

    def __init__(
        self,
        memory_limit: str = "2g",
        cpu_limit: float = 2.0,
        network_mode: str = "bridge"
    ):
        try:
            self.client = docker.from_env()
            self.memory_limit = memory_limit
            self.cpu_limit = cpu_limit
            self.network_mode = network_mode
        except DockerException as e:
            raise RuntimeError(f"无法连接到Docker: {e}")

    async def execute_in_container(
        self,
        image: str,
        command: str,
        timeout: int = 300,
        environment: Optional[Dict[str, str]] = None
    ) -> tuple[str, str, int]:
        """
        在Docker容器中执行命令。

        Args:
            image: Docker镜像名称
            command: 要执行的命令
            timeout: 超时时间（秒）
            environment: 环境变量

        Returns:
            tuple: (stdout, stderr, exit_code)
        """
        try:
            # 确保镜像存在
            await self._ensure_image(image)

            # 在线程池中运行Docker操作（因为docker-py是同步的）
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    self._run_container,
                    image,
                    command,
                    environment
                ),
                timeout=timeout
            )

            return result

        except asyncio.TimeoutError:
            raise TimeoutError(f"容器执行超时（{timeout}秒）")
        except Exception as e:
            raise RuntimeError(f"容器执行失败: {e}")

    def _run_container(
        self,
        image: str,
        command: str,
        environment: Optional[Dict[str, str]]
    ) -> tuple[str, str, int]:
        """在容器中运行命令（同步方法）。"""
        try:
            container = self.client.containers.run(
                image=image,
                command=command,
                detach=False,
                remove=True,
                mem_limit=self.memory_limit,
                nano_cpus=int(self.cpu_limit * 1e9),
                network_mode=self.network_mode,
                environment=environment or {},
                stdout=True,
                stderr=True
            )

            # 容器已自动删除，返回输出
            stdout = container.decode('utf-8') if isinstance(container, bytes) else str(container)
            return stdout, "", 0

        except ContainerError as e:
            return "", str(e), e.exit_status
        except Exception as e:
            return "", str(e), 1

    async def _ensure_image(self, image: str) -> None:
        """确保Docker镜像存在，不存在则拉取。"""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._pull_image_if_needed, image)

    def _pull_image_if_needed(self, image: str) -> None:
        """拉取镜像（如果不存在）。"""
        try:
            self.client.images.get(image)
        except ImageNotFound:
            print(f"拉取Docker镜像: {image}")
            self.client.images.pull(image)

    def list_containers(self) -> list:
        """列出所有运行中的容器。"""
        return self.client.containers.list()

    def cleanup_containers(self) -> int:
        """清理所有停止的容器。"""
        containers = self.client.containers.list(all=True, filters={"status": "exited"})
        count = len(containers)
        for container in containers:
            container.remove()
        return count

    def close(self) -> None:
        """关闭Docker客户端。"""
        if self.client:
            self.client.close()
