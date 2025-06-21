mod my_future;

extern crate futures;

use std::time::Duration;
use crate::my_future::{new_executor_and_spawner, TimerFuture};




fn main() {
    let (executor, spawner) = new_executor_and_spawner();

    spawner.spawn(
        async {
            println!("Task 1");
            TimerFuture::new(Duration::new(2, 0)).await;
            println!("Task 1 end");
        }
    );

    spawner.spawn(
        async {
            println!("Task 2");
        }
    );
    println!("运行时启动: 等待任务完成...");
    drop(spawner);

    executor.run();

    println!("所有任务执行完毕")

}