use std::future::Future;
use std::pin::Pin;
use std::sync::{mpsc, Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::Duration;
use futures::task::{waker, ArcWake};

struct Task {
    future: Mutex<Pin<Box<dyn Future<Output = ()> + Send>>>,
    task_sender: mpsc::Sender<Arc<Task>>,
}

impl ArcWake for Task {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        // 克隆 Arc<Task> 并发送
        let cloned = arc_self.clone();
        arc_self.task_sender.send(cloned).expect("任务队列已关闭");
    }
}
pub struct Executor {
    ready_queue:  mpsc::Receiver<Arc<Task>>,
}
#[derive(Clone)]

pub struct Spawner {
    task_sender: mpsc::Sender<Arc<Task>>,
}

impl Spawner {
    pub(crate) fn spawn(&self, future: impl Future<Output = ()> + 'static + Send) {
        let task = Arc::new(Task{
            future: Mutex::new(Box::pin(future)),
            task_sender: self.task_sender.clone(),
        });
        self.task_sender.send(task).expect("任务队列已关闭")
    }
}

impl Executor {
    pub(crate) fn run(&self) {
        while let Ok(task) = self.ready_queue.recv() {
            let wake = waker(task.clone());
            let mut context = Context::from_waker(&wake);

            let mut future = task.future.lock().unwrap();

            if  future.as_mut().poll(&mut context).is_pending() {
                println!("任务完成")
            }
        }
    }
}

pub fn new_executor_and_spawner() -> (Executor, Spawner) {
    const MAX_QUEUED_TASKS: usize = 10_000;
    let (task_sender, ready_queue) = mpsc::channel();
    (Executor{ready_queue}, Spawner{task_sender})
}


pub struct TimerFuture {
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
    pub fn new(duration: Duration) -> Self {
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
