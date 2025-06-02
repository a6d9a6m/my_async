axnet 使用指南

# 引言
axnet 是 ArceOS 中的网络模块，它基于 smoltcp 提供了一套易于使用的 TCP/IP 网络接口。本指南将带你了解如何使用 axnet 完成常见的网络任务，如初始化网络、进行 TCP 通信、UDP 通信以及 DNS 解析。

在开始之前，请确保 ArceOS 环境已基本就绪，并且拥有一个可用的网络接口驱动程序。具体环境部署请查阅项目的README


## 第一步：初始化网络
在你的应用程序中使用任何网络功能之前，首要任务是初始化 axnet 的网络子系统。这通过调用 axnet::init_network() 函数来完成。

### 重要性：
此函数负责设置底层的网络接口、IP 地址、网关等信息，并准备好 smoltcp 网络栈以供使用。

如何调用：
你需要向 init_network() 函数提供一个 AxDeviceContainer<AxNetDevice> 类型的参数，它包含了系统中可用的网络设备。axnet 会从中选择一个设备来使用。

```Rust

// 概念性代码 - 实际实现可能需要你从驱动层获取 net_devs
// extern crate axnet;
// extern crate axdriver; // 假设 AxNetDevice 和 AxDeviceContainer 从这里来

// use axdriver::{AxDeviceContainer, AxNetDevice}; // 示例路径

fn my_network_init_task(net_devs: AxDeviceContainer<AxNetDevice>) {
if net_devs.is_empty() {
log::error!("No network devices found!");
return;
}
axnet::init_network(net_devs);
log::info!("Network initialized!");
}
```
### 配置：
axnet (通过其 smoltcp_impl 后端) 会尝试从环境变量 AX_IP（IP 地址）和 AX_GW（网关地址）中读取网络配置。如果这些环境变量未设置，可能会使用代码中定义的默认值或导致配置不完整。DNS 服务器地址默认为 "8.8.8.8"。

使用 TCP
TCP (Transmission Control Protocol) 提供可靠的、面向连接的字节流服务。axnet 通过 TcpSocket 结构体来支持 TCP 通信。

1. 创建 TCP 客户端
   TCP 客户端主动发起连接到服务器。

步骤：

创建 TcpSocket：
```Rust
let socket = axnet::TcpSocket::new(); // 创建一个新的 TCP 套接字
```
连接到服务器 (connect)：
你需要知道服务器的 IP 地址和端口号。

```Rust

use core::net::SocketAddr;

// 假设服务器地址为 "192.168.1.100:8080"
let remote_addr_str = "192.168.1.100:8080"; // 实际中可能来自配置或 DNS 解析
let remote_addr: SocketAddr = remote_addr_str.parse().expect("Invalid remote address");

log::info!("Connecting to {}...", remote_addr);
match socket.connect(remote_addr) { // 尝试连接到远程服务器
Ok(()) => {
log::info!("Successfully connected to {}", remote_addr);
// 连接成功，现在可以发送和接收数据
}
Err(e) => {
log::error!("Failed to connect: {:?}", e);
// 处理连接错误，例如 AxError::ConnectionRefused
return;
}
}
```
如果套接字被设置为非阻塞模式，connect() 可能会立即返回 Err(AxError::WouldBlock)。这种情况下，你需要稍后通过轮询检查连接状态，或在阻塞模式下等待连接完成。

发送数据 (send)：

```Rust

let message = b"Hello, server!";
match socket.send(message) { // 发送字节数据
Ok(bytes_sent) => {
log::info!("Sent {} bytes: {:?}", bytes_sent, core::str::from_utf8(message).unwrap_or(""));
}
Err(e) => {
log::error!("Failed to send data: {:?}", e);
// 处理发送错误
}
}
```
接收数据 (recv)：

```Rust

let mut buffer = [0u8; 1024]; // 定义一个接收缓冲区
match socket.recv(&mut buffer) { // 从套接字接收数据
Ok(0) => {
log::info!("Connection closed by peer.");
// 对端关闭了连接
}
Ok(bytes_received) => {
let received_data = &buffer[..bytes_received];
log::info!("Received {} bytes: {:?}", bytes_received, core::str::from_utf8(received_data).unwrap_or(""));
// 处理接收到的数据
}
Err(e) => {
log::error!("Failed to receive data: {:?}", e);
// 处理接收错误，例如在非阻塞模式下的 AxError::WouldBlock
}
}
```
关闭连接 (shutdown)：
完成通信后，应该关闭套接字。

Rust

if let Err(e) = socket.shutdown() { // 关闭 TCP 套接字
log::error!("Failed to shutdown socket: {:?}", e);
} else {
log::info!("Socket shutdown successfully.");
}
// TcpSocket 在 Drop 时也会尝试关闭和清理资源
非阻塞操作：
你可以使用 socket.set_nonblocking(true) 将套接字设置为非阻塞模式。在这种模式下，connect、send、recv 等操作如果不能立即完成，会返回 Err(AxError::WouldBlock)。你的应用程序需要处理这种情况，通常是通过稍后重试或使用轮询机制 (如 socket.poll() 结合 axnet::poll_interfaces())。

2. 创建 TCP 服务器
   TCP 服务器监听指定的端口，等待客户端连接。

步骤：

创建 TcpSocket：

Rust

let listener_socket = axnet::TcpSocket::new(); // 为监听器创建一个套接字
绑定到本地地址和端口 (bind)：
服务器需要绑定到一个本地 IP 地址和端口上才能接受连接。

Rust

use core::net::SocketAddr;

let local_addr_str = "0.0.0.0:12345"; // 监听所有网络接口的 12345 端口
let local_addr: SocketAddr = local_addr_str.parse().expect("Invalid local address");

if let Err(e) = listener_socket.bind(local_addr) { // 绑定套接字到本地地址
log::error!("Failed to bind to {}: {:?}", local_addr, e);
// 处理绑定错误，例如 AxError::AddrInUse
return;
}
log::info!("Socket bound to {}", local_addr);
如果 local_addr 中的端口号为 0，bind 会自动选择一个可用的临时端口。

开始监听连接 (listen)：
让套接字进入监听状态，准备接受客户端连接。

Rust

if let Err(e) = listener_socket.listen() { // 开始监听连接
log::error!("Failed to listen: {:?}", e);
return;
}
log::info!("Listening on {}...", local_addr);
listen() 内部会使用 LISTEN_TABLE 来管理监听状态。

接受客户端连接 (accept)：
当有客户端请求连接时，accept 方法会返回一个新的 TcpSocket，代表与该特定客户端的连接。原始的 listener_socket 继续监听其他连接。

Rust

loop { // 主循环，持续接受连接
log::info!("Waiting for a client to connect...");
match listener_socket.accept() { // 接受一个新的客户端连接
Ok(client_socket) => {
// 获取客户端地址信息
let peer_addr_info = match client_socket.peer_addr() { // 获取对端地址
Ok(addr) => format!("{}", addr),
Err(_) => "unknown peer".to_string(),
};
log::info!("Accepted connection from {}", peer_addr_info);

            // 为每个客户端连接创建一个新任务或线程来处理 (概念性)
            // axtask::spawn(handle_client(client_socket)); // 假设有任务系统

            // --- 或者在当前任务/线程中简单处理 ---
            handle_client_synchronously(client_socket, &peer_addr_info);
            // --- 示例结束 ---
        }
        Err(e) => {
            log::error!("Failed to accept connection: {:?}", e);
            // 如果是 WouldBlock，可以继续循环或 yield
            if matches!(e, axerrno::AxError::WouldBlock) {
                // 在非阻塞模式下，没有挂起的连接
                // 需要确保 poll_interfaces() 被调用以驱动网络栈
                axnet::poll_interfaces(); // 轮询网络接口
                axtask::yield_now(); // 让出 CPU，稍后重试 (假设在任务环境中)
                continue;
            }
            // 其他错误可能需要停止服务器
            break;
        }
    }
}

// 辅助函数：同步处理客户端（简单示例）
fn handle_client_synchronously(client_socket: axnet::TcpSocket, peer_info: &str) {
log::info!("Handling client {} synchronously...", peer_info);
let mut buffer = [0u8; 1024];
match client_socket.recv(&mut buffer) {
Ok(0) => log::info!("Client {} disconnected.", peer_info),
Ok(n) => {
let received_data = &buffer[..n];
log::info!("Received from {}: {:?}", peer_info, core::str::from_utf8(received_data).unwrap_or(""));
// 例如，回显数据
if let Err(e) = client_socket.send(received_data) {
log::error!("Error sending data to {}: {:?}", peer_info, e);
}
}
Err(e) => log::error!("Error receiving from {}: {:?}", peer_info, e),
}
client_socket.shutdown().ok(); // 关闭与此客户端的连接
log::info!("Finished handling client {}.", peer_info);
}
在实际应用中，通常会为每个 accept 成功的连接创建一个新的任务或线程来并发处理，以避免阻塞主监听循环。

与客户端通信：
使用 accept 返回的 client_socket 上的 send 和 recv 方法与特定客户端通信，方式与 TCP 客户端类似。

关闭连接：
当与特定客户端的通信结束后，应关闭对应的 client_socket (client_socket.shutdown())。当服务器不再需要监听时，也应关闭 listener_socket (listener_socket.shutdown())。