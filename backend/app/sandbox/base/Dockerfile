# B2 沙箱基础镜像 —— 依赖在【构建期】装好，运行期禁止 pip（PRD §7.3 / B2 模块设计 T3）
#
# 为什么必须预置：容器挂在 network_disabled 下**没有出网**，运行期 `pip install`
# 必然失败；而把依赖装进运行期还有第二个更隐蔽的代价 —— 探针结果会与「镜像源当时
# 可不可用、拉到的是哪个版本」耦合，同一份源码两次评估可能得到不同结论，不可复现。
#
# 构建（在能访问沙箱宿主的机器上执行；本项目本机无 Docker，走 ECS）：
#   docker build -f app/sandbox/base/Dockerfile -t asa/sandbox-base:latest .
#
# ⚠️ 需要新增依赖时**改这里并重建镜像**，不要在探针里现装。

FROM python:3.12-slim

# 基础运行时依赖。被扫描工程自身的依赖不会自动进来（那需要在控制面解析
# requirements.txt 并重建镜像），当前只覆盖最常见的 Python Web 靶场形态。
# 版本钉死到具体补丁号：镜像名 `asa/sandbox-base:latest` 已经是个可变引用，
# 内部依赖再浮动的话，「同一 tag 两次构建行为不同」就无从排查。
RUN pip install --no-cache-dir \
        requests==2.32.3 \
        Flask==3.0.3 \
        SQLAlchemy==2.0.36 \
    && find /usr/local/lib/python3.12 -name '__pycache__' -prune -exec rm -rf {} +

# 非 root 运行：容器被逃逸时拿不到 root。同时**不要**给它任何 capability
# （SandboxService 在 HostConfig 里 cap_drop=ALL），两边是一致的。
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin sandbox

# 源码的只读挂载点（host 侧路径由远端 daemon 解析，见 ContainerSpec.source_mount）。
# 目录先建出来，避免容器内 workdir 不存在时的行为随 Docker 版本变化。
RUN mkdir -p /workspace && chown sandbox:sandbox /workspace
WORKDIR /workspace

USER sandbox

# 探针在容器内用标准库请求 localhost:<port>，响应经 stdout 回传（设计 T8）——
# 不发布端口、不建隧道，所以这里不需要 EXPOSE。
CMD ["python", "-c", "import sys; sys.stderr.write('sandbox-base image: no default command\n'); sys.exit(0)"]
