FROM fuzzware:fuzzware-hoedur-eval

USER root
RUN apt update -q
RUN apt install -qy \
    clang \
    curl \
    git \
    libfdt-dev \
    libglib2.0-dev \
    libpixman-1-dev \
    libxcb-shape0-dev \
    libxcb-xfixes0-dev \
    ninja-build \
    patchelf \
    pkg-config \
    python3-psutil \
    zstd

# install Rust
USER user
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --no-modify-path --default-toolchain 1.89.0
ENV PATH="${PATH}:/home/user/.cargo/bin"
ENV LD_LIBRARY_PATH="/home/user/.cargo/bin/"

# set git user
ENV GIT_COMMITTER_NAME=Hoedur
ENV GIT_COMMITTER_EMAIL=user@hoedur

# get hoedur + add eval patches
ENV HOEDUR=/home/user/hoedur
RUN git clone https://github.com/fuzzware-fuzzer/hoedur.git $HOEDUR/
RUN cd $HOEDUR && git checkout c94f944bef49e9bf5fbc316389754349444a784a

COPY --chown=user patches/ $HOEDUR/patches/
WORKDIR $HOEDUR

# install hoedur (emulator + fuzzer) - baseline versions of paper
RUN cargo install --path $HOEDUR/hoedur \
    --bin hoedur-arm && \
    cp $HOEDUR/target/release/libqemu-system-arm.release.so $HOME/.cargo/bin/ && \
    # install hoedur variants
    patches/build.sh dma && \
    patches/build.sh pemu

# Add latest pemu version and build again
RUN mkdir -p pemu && rm -rf pemu/*
COPY --chown=user pemu/ $HOEDUR/pemu/

# Build remaining hoedur tools
RUN cargo install --path $HOEDUR/hoedur \
    --bin hoedur-convert-fuzzware-config && \
    cargo install --path $HOEDUR/hoedur-analyze \
    --bin hoedur-coverage-list \
    --bin hoedur-eval-crash \
    --bin hoedur-eval-executions \
    --bin hoedur-merge-report \
    --bin hoedur-plot-data \
    --bin hoedur-reproducer && \
    cargo clean

# add hoedur scripts to python path
ENV PYTHONPATH="/home/user/hoedur/scripts/"

# set BASEDIR / WORKDIR
ENV BASEDIR="/home/user/hoedur-experiments"
WORKDIR $BASEDIR
