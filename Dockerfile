FROM debian:testing
COPY . /asteroid
WORKDIR /asteroid
RUN bash install.sh
ENV PATH="/root/.local/bin:/root/go/bin:$PATH"
RUN uv sync
ENTRYPOINT ["uv", "run", "asteroid.py"]