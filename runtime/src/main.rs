mod my_future;

extern crate futures;

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::Duration;
use crate::my_future::new_executor_and_spawner;

struct TimerFuture {
    shared_state: Arc<Mutex<SharedState>>,
}

struct SharedState {
    completed: bool,
    waker: Option<Waker>,
}

impl Future for TimerFuture {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut shared_state = self.shared_state.lock().unwrap();
        if shared_state.completed {
            Poll::Ready(())
        } else {
            // 还没完成，存储 Waker，以便之后唤醒
            // cx.waker() 返回的是对当前 Waker 的引用
            shared_state.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl TimerFuture {
    fn new(duration: Duration) -> Self {
        let shared_state = Arc::new(Mutex::new(SharedState {
            completed: false,
            waker: None,
        }));

        let thread_shared_state = shared_state.clone();
        thread::spawn(move || {
            thread::sleep(duration);
            let mut shared_state = thread_shared_state.lock().unwrap();
            // 标记为完成
            shared_state.completed = true;
            // 如果在 poll 之后有 Waker 被存储了，就调用 wake()
            if let Some(waker) = shared_state.waker.take() {
                waker.wake()
            }
        });

        TimerFuture { shared_state }
    }
}


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