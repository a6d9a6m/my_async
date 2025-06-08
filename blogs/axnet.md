# axnet
**注：target里面有doc文件夹，那里面是使用cargo doc生成的文件夹，是可以交互的html文件，可以一起阅读增进理解**

axnet 是 ArceOS 的网络模块。它为 TCP/UDP 通信提供了统一的网络原语，支持多种底层网络栈。当前，主要支持并默认使用 smoltcp 作为底层网络栈。

## 主要功能
该模块的核心功能包括：

TcpSocket: 提供类 POSIX API 的 TCP 套接字。

UdpSocket: 提供类 POSIX API 的 UDP 套接字。

dns_query: 用于执行 DNS 查询的功能。

网络接口初始化和轮询。

网络吞吐量基准测试。

![本地路径](axnet.png)
## Cargo 特性
smoltcp: 使用 smoltcp 作为底层网络栈。此特性默认启用。

# 模块组织
axnet 模块的源代码结构如下：

lib.rs: 位于模块的顶层 (例如 axnet/src/lib.rs)，是整个模块的入口，定义了公共 API 并组织了内部实现模块。

smoltcp_impl/: 这是一个子目录 (例如 axnet/src/smoltcp_impl/)，包含了基于 smoltcp 的具体网络协议实现。

mod.rs: smoltcp_impl 模块的核心，负责初始化网络接口、管理套接字集合，并定义了与底层硬件设备交互的包装器。

tcp.rs: TcpSocket 的具体实现。

udp.rs: UdpSocket 的具体实现。

dns.rs: DNS 查询逻辑的实现，包括 DnsSocket 结构体。（注：这些查询与链接都是直接创建完整结构体十分直观的实现）

addr.rs: 提供 std::net 和 smoltcp 地址类型之间的转换工具函数。(注：目前没有IPV6的地址)

listen_table.rs: TCP 服务器监听队列 ListenTable 的实现，用于管理进入的连接请求。

bench.rs: 实现了网络传输和接收带宽的基准测试功能。

lib.rs 通过 mod smoltcp_impl; use smoltcp_impl as net_impl; 来引用和使用 smoltcp_impl 模块中定义的具体实现。
# 在项目里的实现
**这里的功能在项目里实际上是通过宏定义将这些方法作为rustapi接口的实现**

整体而言，是一个(以TCP的链接为例子)[axnet](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/tcp.rs#L121) 
-> [arceos_api//src/impl/net.rs](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/api/arceos_api/src/imp/net.rs#L33) 
-> [宏定义](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/api/arceos_api/src/lib.rs#L292)
-> [ulib/axstd](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/ulib/axstd/src/net/tcp.rs#L27) 
-> [app](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/examples/httpclient/src/main.rs#L27)

axruntime中最开始整个系统的初始化
net.rs里面有一层一对一的映射，将底层投影到api，api又通过宏定义实现了ulib。这里在宏定义那里是解耦的，就是说如果宏定义为实现，
rust会生成空函数，如果调用了会报错。宏定义定义的会直接成为axstd的基础实现，axstd就直达应用层了
# 初始化与配置
## 网络初始化
通过调用 [axnet::init_network(net_devs: AxDeviceContainer<AxNetDevice>)](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/lib.rs#L41C1-L41C68) 函数来初始化网络子系统。此函数会获取一个可用的网络接口控制器 (NIC) 设备，并用它来初始化 smoltcp_impl 后端。
在 smoltcp_impl::init() 内部：
1. 会为选定传入的网络设备创建一个 InterfaceWrapper (名为 ETH0)。
2. 配置 MAC 地址。
3. 从环境变量 [AX_IP](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/mod.rs#L38) (IP 地址) 和 AX_GW (网关地址) 中读取网络配置。默认的 DNS 服务器地址为 "8.8.8.8"。IP 地址前缀长度默认为 24。(这四个常量一起定义的)
4. 初始化全局的套接字集合 SOCKET_SET (类型为 SocketSetWrapper) 和 TCP 监听表 LISTEN_TABLE。

## 常量和配置
一些重要的常量：（在一起定义的）

[STANDARD_MTU](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/mod.rs#L43): 1500 字节。

[TCP/UDP 接收/发送缓冲区大小](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/mod.rs#L47): 均为 64KB。

[TCP 监听队列大小 (LISTEN_QUEUE_SIZE)](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/mod.rs#L51): 512。

# 核心组件与 API

## TcpSocket (TCP 套接字)
TcpSocket 提供了面向连接的可靠数据传输服务。

### 创建: 
[TcpSocket::new()](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/tcp.rs#L50)

这里state使用的是rust的原子类型，访问修改是需要通过锁进行的
创建一个新的 TCP 套接字，初始状态为 CLOSED。

### 客户端操作:
[**connect(remote_addr: SocketAddr) -> AxResult:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/tcp.rs#L121)

连接到指定的远程地址和端口。

首先，调用update_state更新状态，这里涉及到套接字的线程调用，[update更新状态时会首先把套接字状态从CLOSED设置为BUSY](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/tcp.rs#L369)，
其他线程调用update_state检查套接字不是CLOSED后会返回报错，从而保证只有当前线程在访问进行状态更改。update_state执行完之后会将套接字状态更改为CONECTING，以让当前线程进行
接下来的独有操作。最后当前线程会把套接字状态更改为CONNECTED，让给其他线程

然后是找一个本地的端口，调用bound_endpoint()，如果port不为0(意思是申请过了)，就继续启用，如果为0，就调用get_ephemeral_port
重新分配一个端口

ETH0,网络设备

确保独有访问后写入申请到的地址端口（unsafe里的）

```rust
/// Connects to the given address and port.
    ///
    /// The local port is generated automatically.
    pub fn connect(&self, remote_addr: SocketAddr) -> AxResult {
        self.update_state(STATE_CLOSED, STATE_CONNECTING, || {
            /*
            ...
             */
            let bound_endpoint = self.bound_endpoint()?;
            let iface = &ETH0.iface;
            let (local_endpoint, remote_endpoint) = SOCKET_SET
                .with_socket_mut::<tcp::Socket, _, _>(handle, |socket| {
                    socket
                        .connect(iface.lock().context(), remote_endpoint, bound_endpoint)
                        .or_else(|e| match e {
                            ConnectError::InvalidState => {
                                ax_err!(BadState, "socket connect() failed")
                            }
                            ConnectError::Unaddressable => {
                                ax_err!(ConnectionRefused, "socket connect() failed")
                            }
                        })?;
                    Ok((
                        socket.local_endpoint().unwrap(),
                        socket.remote_endpoint().unwrap(),
                    ))
                })?;
            unsafe {
                self.local_addr.get().write(local_endpoint);
                self.peer_addr.get().write(remote_endpoint);
                self.handle.get().write(Some(handle));
            }
            Ok(())
        })
        .unwrap_or_else(|_| ax_err!(AlreadyExists, "socket connect() failed: already connected"))?; // EISCONN
        if self.is_nonblocking() {
            Err(AxError::WouldBlock)
        } else {
            self.block_on(|| {
                let PollState { writable, .. } = self.poll_connect()?;
                if !writable {
                    Err(AxError::WouldBlock)
                } else if self.get_state() == STATE_CONNECTED {
                    Ok(())
                } else {
                    ax_err!(ConnectionRefused, "socket connect() failed")
                }
            })
        }
    }
```
如果套接字是非阻塞的，此方法会立即返回 Err(AxError::WouldBlock),否则会调用[block_on()](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/tcp.rs#L477)。
block_on会根据is_nonblocking()尝试执行传入的函数（这里是那个闭包），如果设置为非阻塞直接执行，如果是阻塞会调用poll_interface,一路向内调用，执行mod.rs
的[poll()](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/mod.rs#L173)
然后调用下面依赖的iface的poll。
```rust
pub fn poll(&self, sockets: &Mutex<SocketSet>) {
    let mut dev = self.dev.lock();
    let mut iface = self.iface.lock();
    let mut sockets = sockets.lock();
    let timestamp = Self::current_time();
    iface.poll(timestamp, dev.deref_mut(), &mut sockets);
}
```
这里再说一下poll，iface的poll的注释有写：
```rust
/// Transmit packets queued in the given sockets, and receive packets queued
/// in the device.
///
/// This function returns a boolean value indicating whether any packets were
/// processed or emitted, and thus, whether the readiness of any socket might
/// have changed.

```
poll主要是功能就是接受数据和发送数据，每次调用都会把接收队列内容全部获取，发送队列全部发送，block_on会一直不断调用poll（可能上次数据还没到接收队列里）。直到拿到想要的数据



### 服务端操作:
**[bind(local_addr: SocketAddr) -> AxResult](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/tcp.rs#L182):**

将套接字绑定到本地 IP 地址和端口。如果端口为 0，则会自动分配一个临时端口。

listen() -> AxResult: 开始监听绑定的地址和端口上的传入连接。内部使用 ListenTable。

如果多个线程同时或先后对同一个套接字调用 listen()，只有第一次调用会真正执行监听的逻辑，所有后续的调用都会被安全地忽略，并直接返回成功 (Ok(()))，
而不会报错.目的是这种设计使得 listen() 操作变得幂等（Idempotent）。也就是说，调用一次 listen() 和调用多次 listen() 的最终结果是一样的，
并且都不会产生“已经处于监听状态”之类的错误。
```rust
    /// It's must be called after [`bind`](Self::bind) and before
    /// [`accept`](Self::accept).
    pub fn listen(&self) -> AxResult {
        self.update_state(STATE_CLOSED, STATE_LISTENING, || {
            let bound_endpoint = self.bound_endpoint()?;
            unsafe {
                (*self.local_addr.get()).port = bound_endpoint.port;
            }
            LISTEN_TABLE.listen(bound_endpoint)?;
            debug!("TCP socket listening on {}", bound_endpoint);
            Ok(())
        })
        .unwrap_or(Ok(())) // ignore simultaneous `listen`s.
    }
```

[**accept() -> AxResult<TcpSocket>:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/tcp.rs#L225)

接受一个新的连接。

函数会等待直到一个新的tcp链接确立，调用block_on非阻塞监听等待。(具体过程还是一路poll，前面已说过)
```rust
    pub fn accept(&self) -> AxResult<TcpSocket> {
        if !self.is_listening() {
            return ax_err!(InvalidInput, "socket accept() failed: not listen");
        }

        // SAFETY: `self.local_addr` should be initialized after `bind()`.
        let local_port = unsafe { self.local_addr.get().read().port };
        self.block_on(|| {
            let (handle, (local_addr, peer_addr)) = LISTEN_TABLE.accept(local_port)?;
            debug!("TCP socket accepted a new connection {}", peer_addr);
            Ok(TcpSocket::new_connected(handle, local_addr, peer_addr))
        })
    }
```
如果套接字是非阻塞的且没有挂起的连接，则返回 Err(AxError::WouldBlock)。

成功时返回一个新的 TcpSocket 实例，代表与客户端建立的连接。

### 数据收发:
[**send(buf: &[u8]) -> AxResult<usize>:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/tcp.rs#L306) 

发送数据。把要发送的数据放到指定的buffer里

[**recv(buf: &mut [u8]) -> AxResult<usize>:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/tcp.rs#L273) 

接收数据。把要发送的数据放到指定的buffer里

如果连接已关闭，返回 Ok(0)。

在非阻塞模式下，如果没有数据可读，返回 Err(AxError::WouldBlock)。

### 关闭:
**shutdown() -> AxResult:** 

关闭连接的读取、写入或两者。这会改变套接字状态并可能释放相关资源。
```rust
/// Close the connection.
    pub fn shutdown(&self) -> AxResult {
        // stream
        self.update_state(STATE_CONNECTED, STATE_CLOSED, || {
            let handle = unsafe { self.handle.get().read().unwrap() };
            SOCKET_SET.with_socket_mut::<tcp::Socket, _, _>(handle, |socket| {
                debug!("TCP socket {}: shutting down", handle);
                socket.close();
            });
            unsafe { self.local_addr.get().write(UNSPECIFIED_ENDPOINT) }; // clear bound address
            SOCKET_SET.poll_interfaces();
            Ok(())
        })
        .unwrap_or(Ok(()))?;

        // listener
        self.update_state(STATE_LISTENING, STATE_CLOSED, || {

            let local_port = unsafe { self.local_addr.get().read().port };
            unsafe { self.local_addr.get().write(UNSPECIFIED_ENDPOINT) }; // clear bound address
            LISTEN_TABLE.unlisten(local_port);
            SOCKET_SET.poll_interfaces();
            Ok(())
        })
        .unwrap_or(Ok(()))?;

        // ignore for other states
        Ok(())
    }
```
### 非阻塞模式:
[**is_nonblocking() -> bool:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/tcp.rs#L101) 

检查套接字是否处于非阻塞模式。

[**set_nonblocking(nonblocking: bool):**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/tcp.rs#L114) 

设置套接字的非阻塞模式。

### 状态查询:
[**local_addr() -> AxResult<SocketAddr>:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/tcp.rs#L78) 

获取本地套接字地址。

[**peer_addr() -> AxResult<SocketAddr>:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/tcp.rs#L900)

获取对端套接字地址。

[**poll() -> AxResult<PollState>:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/tcp.rs#L336)

查询套接字的可读/可写状态。注意，这个poll跟上面提到的block_on的poll是不一样的，这个poll的使用是axnet的mod.rs和其他arceos上层api，block_on的poll是轮询


## UdpSocket (UDP 套接字)
UdpSocket 提供了无连接的数据报服务。由于UDOP无状态的，所以不用维持状态机

### 创建: 
[**UdpSocket::new()**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/udp.rs#L27)
```rust
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let socket = SocketSetWrapper::new_udp_socket();
        let handle = SOCKET_SET.add(socket);
        Self {
            handle,
            local_addr: RwLock::new(None),
            peer_addr: RwLock::new(None),
            nonblock: AtomicBool::new(false),
        }
    }
```
创建一个新的 UDP 套接字，并将其添加到全局的 SOCKET_SET 中。
### 操作:
[**bind(local_addr: SocketAddr) -> AxResult:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/udp.rs#L76) 

将套接字绑定到本地IP地址和端口。如果端口为 0，则会自动分配一个临时端口。绑定通过SOXCKET获取套接字可变引用，最后通过smoltcp依赖的
bind进行实际绑定。必须在 send_to 和 recv_from 之前调用。
```rust
    pub fn bind(&self, mut local_addr: SocketAddr) -> AxResult {
        let mut self_local_addr = self.local_addr.write();
        if local_addr.port() == 0 {
            local_addr.set_port(get_ephemeral_port()?);
        }
        /*
        ...
         */
        SOCKET_SET.with_socket_mut::<udp::Socket, _, _>(self.handle, |socket| {
            socket.bind(endpoint).or_else(|e| match e {
                BindError::InvalidState => ax_err!(AlreadyExists, "socket bind() failed"),
                BindError::Unaddressable => ax_err!(InvalidInput, "socket bind() failed"),
            })
        })?;
        /*
        ...
         */
        
    }
```
[**connect(addr: SocketAddr) -> AxResult:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/udp.rs#L137)

将套接字“连接”到指定的远程地址。这允许之后使用 send 和 recv，并过滤只接收来自该远程地址的数据。如果未绑定，则会自动绑定到一个临时端口。必须在[`send`](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/tcp.rs#L306)
和[`recv`](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/tcp.rs#L273).
之前

### 数据收发:
[**send_to(buf: &[u8], remote_addr: SocketAddr) -> AxResult<usize>:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/udp.rs#L105)

将数据发送到指定的远程地址。

[**recv_from(buf: &mut [u8]) -> AxResult<(usize, SocketAddr)>:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/udp.rs#L114)

从套接字接收数据，并返回读取的字节数以及数据的源地址。

[**peek_from(buf: &mut [u8]) -> AxResult<(usize, SocketAddr)>:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/udp.rs#L123)

类似 recv_from，但数据不会从接收队列中移除。

[**send(buf: &[u8]) -> AxResult<usize>:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/udp.rs#L150)

将数据发送到先前 connect 指定的远程地址。

[**recv(buf: &mut [u8]) -> AxResult<usize>:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/udp.rs#L157)

从先前 connect 指定的远程地址接收数据。

### 关闭:
[**shutdown() -> AxResult:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/udp.rs#L174) 

调用SOCKET_SET获取socket可变引用 关闭 UDP 套接字。

### 非阻塞模式:
[**is_nonblocking() -> bool:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/udp.rs#L55)

检查套接字是否处于非阻塞模式。

[**set_nonblocking(nonblocking: bool):**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/udp.rs#L68) 

设置套接字的非阻塞模式。受影响的函数很多，比如recv，recv_from,send,send_to。设置后会立刻返回一个结果，如果能立刻有结果会是ok()
,其他的无论是没有结果还是结果需要等待都会产生error

### 状态查询:(与TCP相同)
[**local_addr() -> AxResult<SocketAddr>:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/udp.rs#L40) 

获取本地套接字地址。

[**peer_addr() -> AxResult<SocketAddr>:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/udp.rs#L49) 

获取（通过 connect 设置的）对端套接字地址。

[**poll() -> AxResult<PollState>:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/udp.rs#L184)

查询套接字的可读/可写状态。

## DNS 解析
[**dns_query(name: &str) -> AxResult<alloc::vec::Vec<IpAddr>>:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/dns.rs#L87) 

执行 DNS A 记录查询，将域名解析为一个或多个 IP 地址。并且内部创建一个临时的 DnsSocket，使用配置的 DNS 服务器 (默认为 "8.8.8.8") 进行查询。

[**query(&self, name: &str, query_type: DnsQueryType) -> AxResult<Vec<IpAddr>>:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/dns.rs#L35)

调用smoltcp的start_query()来创建dns请求，接下来错误处理，后面调用poll_interface()轮询等待结果

```rust
pub fn query(&self, name: &str, query_type: DnsQueryType) -> AxResult<Vec<IpAddr>> {
    /*
    ...
     */
    let query_handle = SOCKET_SET
        .with_socket_mut::<dns::Socket, _, _>(handle, |socket| {
            socket.start_query(iface.lock().context(), name, query_type)
        })
        .map_err(|e| match e {
            StartQueryError::NoFreeSlot => {
                ax_err_type!(ResourceBusy, "socket query() failed: no free slot")
            }
            StartQueryError::InvalidName => {
                ax_err_type!(InvalidInput, "socket query() failed: invalid name")
            }
            StartQueryError::NameTooLong => {
                ax_err_type!(InvalidInput, "socket query() failed: too long name")
            }
        })?;
    loop {
        SOCKET_SET.poll_interfaces();
        /*
        ...
         */
    }
}

```
## 网络栈轮询
[**poll_interfaces()**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/mod.rs#L305)

驱动网络栈处理。它会轮询网络接口，接收传入的数据包并将其分派给相应的套接字，同时发送套接字中排队等待传出的数据包。
(前面block_on提及过)

## 测试部分
有两个网络测试函数，测试系统的数据发送/接收能力

[**bench_transmit():**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/mod.rs#L310) 

测试底层网络设备的最大传输带宽。它会尽可能快地发送大量数据包。

**实际内部的定义：**
```rust
impl DeviceWrapper {
    pub fn bench_transmit_bandwidth(&mut self) {
        // 10 Gb
        const MAX_SEND_BYTES: usize = 10 * GB;
        let mut send_bytes: usize = 0;
        let mut past_send_bytes: usize = 0;
        let mut past_time = InterfaceWrapper::current_time();

        // Send bytes
        while send_bytes < MAX_SEND_BYTES {
            if let Some(tx_token) = self.transmit(InterfaceWrapper::current_time()) {
                AxNetTxToken::consume(tx_token, STANDARD_MTU, |tx_buf| {
                    tx_buf[0..12].fill(1);
                    // ether type: IPv4
                    tx_buf[12..14].copy_from_slice(&[0x08, 0x00]);
                    tx_buf[14..STANDARD_MTU].fill(1);
                });
                send_bytes += STANDARD_MTU;
            }

            let current_time = InterfaceWrapper::current_time();
            if (current_time - past_time).secs() == 1 {
                let gb = ((send_bytes - past_send_bytes) * 8) / GB;
                let mb = (((send_bytes - past_send_bytes) * 8) % GB) / MB;
                let gib = (send_bytes - past_send_bytes) / GB;
                let mib = ((send_bytes - past_send_bytes) % GB) / MB;
                info!(
                    "Transmit: {}.{:03}GBytes, Bandwidth: {}.{:03}Gbits/sec.",
                    gib, mib, gb, mb
                );
                past_time = current_time;
                past_send_bytes = send_bytes;
            }
        }
    }
}
```


[**bench_receive():**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/mod.rs#L315) 

测试底层网络设备的最大接收带宽。它会持续接收数据包并统计速率。

**内部实际定义：**
```rust
impl DeviceWrapper {
    pub fn bench_receive_bandwidth(&mut self) {
        // 10 Gb
        const MAX_RECEIVE_BYTES: usize = 10 * GB;
        let mut receive_bytes: usize = 0;
        let mut past_receive_bytes: usize = 0;
        let mut past_time = InterfaceWrapper::current_time();
        // Receive bytes
        while receive_bytes < MAX_RECEIVE_BYTES {
            if let Some(rx_token) = self.receive(InterfaceWrapper::current_time()) {
                AxNetRxToken::consume(rx_token.0, |rx_buf| {
                    receive_bytes += rx_buf.len();
                });
            }

            let current_time = InterfaceWrapper::current_time();
            if (current_time - past_time).secs() == 1 {
                let gb = ((receive_bytes - past_receive_bytes) * 8) / GB;
                let mb = (((receive_bytes - past_receive_bytes) * 8) % GB) / MB;
                let gib = (receive_bytes - past_receive_bytes) / GB;
                let mib = ((receive_bytes - past_receive_bytes) % GB) / MB;
                info!(
                    "Receive: {}.{:03}GBytes, Bandwidth: {}.{:03}Gbits/sec.",
                    gib, mib, gb, mb
                );
                past_time = current_time;
                past_receive_bytes = receive_bytes;
            }
        }
    }
}
```

# 内部机制简介
## [**InterfaceWrapper (ETH0):**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/mod.rs#L63) 

代表一个网络接口 (如 eth0)。它包装了 smoltcp::iface::Interface 和一个 DeviceWrapper。InterfaceWrapper 负责管理接口的 IP 配置、路由，
并通过其 poll 方法驱动 smoltcp 的核心处理逻辑。（前面block_on处一样，一路到iface的poll，这是iface上面最后一层）

```rust
// In smoltcp_impl/mod.rs
struct InterfaceWrapper {
    name: &'static str,
    ether_addr: EthernetAddress,
    dev: Mutex<DeviceWrapper>,
    iface: Mutex<Interface>,
}

// InterfaceWrapper::poll method:
impl InterfaceWrapper {
// ...
    pub fn poll(&self, sockets: &Mutex<SocketSet>) {
        let mut dev = self.dev.lock();
        let mut iface = self.iface.lock();
        let mut sockets = sockets.lock();
        let timestamp = Self::current_time();
        iface.poll(timestamp, dev.deref_mut(), &mut sockets);
    }
// ...
}
```


## [**DeviceWrapper:**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/mod.rs#L59) 
对 axdriver::AxNetDevice（一个网络硬件驱动的抽象）的包装，实现了 smoltcp::phy::Device trait。它使得 smoltcp 可以通过标准接口与具体的网络硬件交互，
进行数据包的收发。

## [**SocketSetWrapper (SOCKET_SET):**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/mod.rs#L57) 

包装了 smoltcp::iface::SocketSet，并使用 Mutex 进行同步。SocketSet 是 smoltcp 中管理所有活动套接字的容器。SocketSetWrapper 
提供了创建和管理 TCP、UDP、DNS 套接字的辅助方法。

## [**ListenTable (LISTEN_TABLE):**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/listen_table.rs#L44) 

专门为 TCP 服务器设计。当一个 TCP 套接字进入监听状态时，它会在 ListenTable 中注册。ListenTable 维护一个按端口号索引的表，
每个条目包含一个监听端点和已接收但尚未被 accept 的 SYN 包队列 (半连接队列)。


[**snoop_tcp_packet(buf: &[u8], sockets: &mut SocketSet<'_>) -> Result<(), smoltcp::wire::Error>**](https://github.com/arceos-org/arceos/blob/e3ab0a26483ce042b43947ec7d455b08145ea35e/modules/axnet/src/smoltcp_impl/mod.rs#L282)

当新的 TCP SYN 包到达时，snoop_tcp_packet 函数（在 smoltcp_impl/mod.rs 中）会通知 ListenTable 处理。

## 地址转换 (addr.rs): 

提供了一系列 const fn 函数，用于在 ArceOS 标准库的地址类型 (core::net::IpAddr, core::net::SocketAddr) 和 
smoltcp 的地址类型 (smoltcp::wire::IpAddress, smoltcp::wire::IpEndpoint) 之间进行转换。(目前主要支持 IPv4。IPV6支持正在添加中)


